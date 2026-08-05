package nethernet

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

// Dialer encapsulates options for establishing a connection with a NetherNet network through [Dialer.DialContext]
// and other aliases. It allows customizing logging, WebRTC API settings, and contexts for a negotiation.
type Dialer struct {
	// ConnectionID is the unique ID of a Conn being established. If zero, a random value will be automatically
	// set from [rand.Uint64].
	ConnectionID uint64

	// Log is used for logging messages at various log levels. If nil, the default [slog.Logger] will be automatically
	// set from [slog.Default]. Log will be extended when a Conn is being established by [Dialer] with additional attributes
	// such as the connection ID and network ID, and will have a 'src' attribute set to 'dialer' to mark that the Conn
	// has been negotiated by Dialer.
	Log *slog.Logger

	// API specifies custom configuration for WebRTC transports and data channels. If nil, a new [webrtc.API] will be
	// set from [webrtc.NewAPI]. The [webrtc.SettingEngine] of the API should not allow detaching data channels, as it requires
	// additional steps on the Conn (which cannot be determined by the Conn).
	API *webrtc.API

	// Identity specifies the identity presented to the remote peer during
	// connection negotiation.
	//
	// When set to non-nil, an 'a=identity' attribute is attached to the SDP offer
	// and used to authenticate the client and bind its identity to the WebRTC peer
	// connection.
	//
	// When set to nil, no identity assertion is included in the offer.
	Identity *Identity
	// VerifyServerToken verifies the token contained in a server's identity
	// assertion and returns the public key populated in its 'cpk' claim.
	//
	// The returned public key is used to verify the fingerprint assertion
	// carried in the server answer's 'a=identity' attribute.
	//
	// When [Dialer.AllowIdentitylessServer] is set to true, VerifyServerToken may never be called.
	//
	// By default, this is set to a function that only extracts the public key
	// from the token's 'cpk' claim and trusts it unconditionally.
	VerifyServerToken func(ctx context.Context, token, domain string) (*ecdsa.PublicKey, error)

	// AllowIdentitylessServer specifies whether to allow answer SDPs without an
	// 'a=identity' attribute.
	//
	// When set to false, the server must present a valid identity assertion.
	// When set to true, unauthenticated servers are allowed to establish connections.
	//
	// This may be useful when connecting to legacy or custom implementations.
	AllowIdentitylessServer bool

	// ICEGatherPolicy limits which local ICE candidates are gathered for the
	// connection.
	//
	// It may be used to restrict connectivity to specific candidate types, such
	// as relayed candidates from TURN servers only.
	ICEGatherPolicy webrtc.ICEGatherPolicy

	// DisableTrickleICE disables trickle ICE for connection negotiation.
	//
	// When set to true, the dialer waits for ICE gathering to complete and embeds
	// all local candidates in the initial offer SDP. Otherwise, candidates are
	// signaled incrementally as separate [SignalTypeCandidate] signals after the
	// offer is sent.
	//
	// This may slow connection establishment because the initial offer cannot be
	// sent until candidate gathering completes.
	//
	// This behavior can be seen when connecting to dedicated servers with the
	// 'nethernet-disable-trickle-ice' setting property set to 'true'.
	DisableTrickleICE bool
}

// DialContext establishes a Conn with a remote network referenced by the ID. The Signaling is used to signal
// an offer with local candidates, and also to notify incoming signals received from the remote network. The
// [context.Context] may be used to cancel the connection as soon as possible. A Conn may be returned, that is
// ready to receive and send packets.
func (d Dialer) DialContext(ctx context.Context, networkID string, signaling Signaling) (_ *Conn, err error) {
	if d.ConnectionID == 0 {
		d.ConnectionID = rand.Uint64()
	}
	if d.API == nil {
		d.API = webrtc.NewAPI()
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.VerifyServerToken == nil {
		d.VerifyServerToken = func(ctx context.Context, token, domain string) (*ecdsa.PublicKey, error) {
			publicKey, err := claimPublicKey(token, true)
			if err != nil {
				return nil, err
			}
			d.Log.Debug("trusting server identity", "domain", domain)
			return publicKey, nil
		}
	}

	credentials, err := signaling.Credentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain credentials: %w", err)
	}

	// Signals may be received very early when signaling an offer with local candidates.
	signals, stop := d.notifySignals(networkID, signaling)
	defer func() {
		if err != nil {
			stop()
		}
	}()
	c, err := newConn(d.API, gatherOptions(credentials, d.ICEGatherPolicy), d.ConnectionID, networkID, signaling.NetworkID(), dialerConn{
		Dialer: d,
		stop:   stop,
	}, ErrorCodeFailedToCreateOffer)
	if err != nil {
		return nil, fmt.Errorf("create conn: %w", err)
	}
	defer func() {
		if err != nil {
			_ = c.close(fmt.Errorf("dial failure: %w", err))
		}
	}()
	if d.Identity != nil {
		if err := d.Identity.sign(c.description); err != nil {
			return nil, fmt.Errorf("generate identity assertion: %w", err)
		}
	}

	c.sctp.OnDataChannel(func(channel *webrtc.DataChannel) {
		// For client connections, the server should never open a data channel.
		//
		// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
		go c.close(fmt.Errorf("data channel %q was unexpectedly opened by remote peer", channel.Label()))
	})

	disableTrickleICE := shouldDisableTrickleICE(d.DisableTrickleICE, signaling)
	if disableTrickleICE {
		c.description.candidates, err = c.gatherCandidates(ctx)
		if err != nil {
			return nil, fmt.Errorf("gather local candidates (non-trickle ICE): %w", err)
		}
	}

	// Encode an offer using the local parameters!
	offer, err := c.description.encode()
	if err != nil {
		return nil, fmt.Errorf("encode offer: %w", err)
	}
	if err := signaling.Signal(ctx, &Signal{
		Type:         SignalTypeOffer,
		Data:         string(offer),
		ConnectionID: d.ConnectionID,
		NetworkID:    networkID,
	}); err != nil {
		return nil, fmt.Errorf("signal offer: %w", err)
	}

	if !disableTrickleICE {
		if err := c.trickleCandidates(signaling); err != nil {
			return nil, fmt.Errorf("start gathering local candidates: %w", err)
		}
	}

	for {
		select {
		case <-c.ctx.Done():
			return nil, context.Cause(c.ctx)
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				d.signalError(signaling, networkID, ErrorCodeNegotiationTimeoutWaitingForResponse)
			}
			return nil, ctx.Err()
		case <-signaling.Context().Done():
			return nil, context.Cause(signaling.Context())
		case signal, ok := <-signals:
			if !ok {
				return nil, net.ErrClosed
			}
			switch signal.Type {
			case SignalTypeAnswer:
				s := &sdp.SessionDescription{}
				if err := s.UnmarshalString(signal.Data); err != nil {
					d.signalError(signaling, networkID, ErrorCodeFailedToSetRemoteDescription)
					return nil, fmt.Errorf("decode answer: %w", err)
				}
				desc, err := parseDescription(s)
				if err != nil {
					d.signalError(signaling, networkID, ErrorCodeFailedToSetRemoteDescription)
					return nil, fmt.Errorf("parse answer: %w", err)
				}
				if desc.identity != nil {
					publicKey, err := d.VerifyServerToken(ctx, desc.identity.Assertion.Token, desc.identity.IdentityProvider.Domain)
					if err != nil {
						d.signalError(signaling, networkID, ErrorCodeIdentityVerificationFailed)
						return nil, fmt.Errorf("verify server identity token: %w", err)
					}
					if err := desc.identity.verify(desc, publicKey); err != nil {
						d.signalError(signaling, networkID, ErrorCodeIdentityVerificationFailed)
						return nil, fmt.Errorf("verify server identity: %w", err)
					}
					c.publicKey = publicKey
				} else if !d.AllowIdentitylessServer {
					d.signalError(signaling, networkID, ErrorCodeIdentityVerificationFailed)
					return nil, errors.New("identityless answer SDP not allowed")
				}
				for _, candidate := range desc.candidates {
					// Non-trickle ICE connection such as Realms may include candidates in a single SDP.
					if err := c.addRemoteCandidate(candidate); err != nil {
						d.signalError(signaling, networkID, ErrorCodeFailedToSetRemoteDescription)
						return nil, fmt.Errorf("add bundled answer candidate: %w", err)
					}
				}

				go d.handleConn(c, signals)

				select {
				case <-c.ctx.Done():
					return nil, context.Cause(c.ctx)
				case <-ctx.Done():
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						d.signalError(signaling, networkID, ErrorCodeInactivityTimeout)
					}
					if err := context.Cause(c.ctx); err != nil {
						return nil, err
					}
					return nil, ctx.Err()
				case <-c.candidateReceived:
					c.log.Debug("received first candidate")
					if err := d.startTransports(ctx, c, desc); err != nil {
						if errors.Is(err, context.DeadlineExceeded) {
							d.signalError(signaling, networkID, ErrorCodeInactivityTimeout)
						}
						return nil, fmt.Errorf("start transports: %w", err)
					}
					return c, nil
				}
			default:
				err = c.handleSignal(signal)
				if err != nil {
					d.signalError(signaling, networkID, ErrorCodeIncomingConnectionIgnored)
					return nil, fmt.Errorf("handle signal: %w", err)
				}
			}
		}
	}
}

// dialerConn implements negotiator for a Conn negotiated by Dialer.
type dialerConn struct {
	Dialer

	// stop is a function that can be called without parameters, which is returned by
	// [Signaling.Notify] to stop notifying signals from Signaling.
	stop func()
}

// handleClose stops receiving notifications from Signaling for incoming signals and errors.
func (d dialerConn) handleClose(*Conn) {
	d.stop()
}

// log returns the Log of the Dialer and extends it for a Conn with an additional [slog.Attr] of 'src'
// set to 'dialer' to mark that the Conn has been negotiated by Dialer. [Dialer.Log] will always be
// non-nil as it is always set up to the default [slog.Logger] before creating a Conn through newConn.
func (d dialerConn) log() *slog.Logger {
	return d.Log.With(slog.String("src", "dialer"))
}

// signalError sends a SignalTypeError to the remote connection using the
// provided [Signaling] implementation, remote network ID, and error code.
func (d Dialer) signalError(signaling Signaling, networkID string, code int) {
	go func() {
		ctx, cancel := context.WithTimeout(signaling.Context(), signalErrorTimeout)
		defer cancel()
		_ = signaling.Signal(ctx, &Signal{
			Type:         SignalTypeError,
			Data:         strconv.Itoa(code),
			ConnectionID: d.ConnectionID,
			NetworkID:    networkID,
		})
	}()
}

const signalErrorTimeout = time.Second * 2

// startTransports starts the ICE transport as [webrtc.ICERoleControlling],
// then starts DTLS and SCTP using the parameters from the remote description.
// After SCTP is established, it creates the 'ReliableDataChannel' and
// 'UnreliableDataChannel'. All operations respect the provided [context.Context].
func (d Dialer) startTransports(ctx context.Context, conn *Conn, desc *description) error {
	conn.log.Debug("starting ICE transport as controller")
	iceRole := webrtc.ICERoleControlling
	if err := conn.ice.StartContext(ctx, nil, desc.ice, &iceRole); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}

	conn.log.Debug("starting DTLS transport", slog.String("remoteRole", desc.dtls.Role.String()))
	if err := conn.dtls.StartContext(ctx, desc.dtls); err != nil {
		return fmt.Errorf("start DTLS: %w", err)
	}

	conn.log.Debug("starting SCTP transport")
	if err := withContextCancel(ctx, func() error {
		return conn.sctp.Start(desc.sctp)
	}, func() {
		_ = conn.sctp.Stop()
	}); err != nil {
		return fmt.Errorf("start SCTP: %w", err)
	}
	for r := range messageReliabilityCapacity {
		c, err := d.API.NewDataChannel(conn.sctp, r.Parameters())
		if err != nil {
			return fmt.Errorf("create %s: %w", r.Parameters().Label, err)
		}
		if existing := conn.storeChannel(r, wrapDataChannel(c, r, conn)); existing != nil {
			return fmt.Errorf("data channel created for same reliability parameters: %q", r.Parameters().Label)
		}
	}
	return nil
}

// handleConn handles incoming Signals signaled from the remote connection and calls Conn.handleSignal
// to handle them within the Conn. It returns when the Conn context is canceled.
func (d Dialer) handleConn(conn *Conn, signals <-chan *Signal) {
	for {
		select {
		case <-conn.ctx.Done():
			return
		case signal, ok := <-signals:
			if !ok {
				// Signals channel closed, connection should be closed as well
				// when the notifier explicitly ends. Do not also watch Signaling.Context here:
				// established WebRTC data connections may outlive the signaling transport.
				if err := conn.Close(); err != nil {
					conn.log.Error("error closing conn", slog.Any("error", err))
				}
				return
			}
			switch signal.Type {
			case SignalTypeCandidate, SignalTypeError:
				if err := conn.handleSignal(signal); err != nil {
					conn.log.Error("error handling signal", slog.Any("error", err))
				}
			}
		}
	}
}

// notifySignals registers a channel to the Signaling to receive notifications of incoming Signals that has
// the same network ID and same ConnectionID of Dialer. A channel for filtered signals and a function to stop
// receiving notifications will be returned.
func (d Dialer) notifySignals(networkID string, signaling Signaling) (<-chan *Signal, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	var (
		notifier = &dialerNotifier{
			Dialer:    d,
			networkID: networkID,
			signals:   make(chan *Signal, 64),
			ctx:       ctx,
		}
		once sync.Once
	)
	stop := signaling.Notify(notifier)

	return notifier.signals, func() {
		once.Do(func() {
			cancel()
			stop()
		})
	}
}

// dialerNotifier notifies incoming Signals and errors.
type dialerNotifier struct {
	Dialer

	// signals is the channel which filtered signals are sent to the
	// [Dialer.DialContext] caller.
	signals chan *Signal

	// ctx is a background context for this notifier which is canceled
	// when the connection is closed or the notifier stops receiving signals.
	ctx context.Context

	// networkID is the remote network ID used to filter incoming signals.
	// Along with [Dialer.ConnectionID], it is used to multiplex signals matching both identifiers.
	networkID string
}

// NotifySignal notifies an incoming Signal received from the Signaling implementation.
func (d *dialerNotifier) NotifySignal(signal *Signal) bool {
	if signal.ConnectionID != d.ConnectionID || signal.NetworkID != d.networkID {
		return false
	}
	select {
	case d.signals <- signal:
		return true
	case <-d.ctx.Done():
		return false
	default:
		d.Log.Warn("dropping signal because channel buffer is full", slog.Any("signal", signal))
		return false
	}
}
