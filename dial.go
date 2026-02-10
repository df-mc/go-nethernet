package nethernet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"

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
}

// DialContext establishes a Conn with a remote network referenced by the ID. The Signaling is used to signal
// an offer with local candidates, and also to notify incoming signals received from the remote network. The
// [context.Context] may be used to cancel the connection as soon as possible. A Conn may be returned, that is
// ready to receive and send packets.
func (d Dialer) DialContext(ctx context.Context, networkID string, signaling Signaling) (conn *Conn, err error) {
	if d.ConnectionID == 0 {
		d.ConnectionID = rand.Uint64()
	}
	if d.API == nil {
		d.API = webrtc.NewAPI()
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}

	credentials, err := signaling.Credentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain credentials: %w", err)
	}
	gatherer, err := d.API.NewICEGatherer(gatherOptions(credentials))
	if err != nil {
		return nil, fmt.Errorf("create ICE gatherer: %w", err)
	}

	var (
		candidates     []webrtc.ICECandidate
		gatherFinished = make(chan struct{})
	)
	gatherer.OnLocalCandidate(func(candidate *webrtc.ICECandidate) {
		if candidate == nil {
			close(gatherFinished)
			return
		}
		candidates = append(candidates, *candidate)
	})
	if err := gatherer.Gather(); err != nil {
		return nil, fmt.Errorf("gather local candidates: %w", err)
	}
	select {
	case <-ctx.Done():
		_ = gatherer.Close()
		return nil, ctx.Err()
	case <-gatherFinished:
		ice := d.API.NewICETransport(gatherer)
		dtls, err := d.API.NewDTLSTransport(ice, nil)
		if err != nil {
			return nil, fmt.Errorf("create DTLS transport: %w", err)
		}
		sctp := d.API.NewSCTPTransport(dtls)

		iceParams, err := ice.GetLocalParameters()
		if err != nil {
			return nil, fmt.Errorf("obtain local ICE parameters: %w", err)
		}
		dtlsParams, err := dtls.GetLocalParameters()
		if err != nil {
			return nil, fmt.Errorf("obtain local DTLS parameters: %w", err)
		}
		if len(dtlsParams.Fingerprints) == 0 {
			return nil, errors.New("local DTLS parameters has no fingerprints")
		}
		sctpCapabilities := sctp.GetCapabilities()

		// Signals may be received very early when signaling an offer with local candidates.
		signals, stop := d.notifySignals(networkID, signaling)
		defer func() {
			if err != nil {
				stop()
			}
		}()

		// Encode an offer using the local parameters!
		dtlsParams.Role = webrtc.DTLSRoleServer
		offer, err := description{
			ice:  iceParams,
			dtls: dtlsParams,
			sctp: sctpCapabilities,
		}.encode()
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
		for i, candidate := range candidates {
			if err := signaling.Signal(ctx, &Signal{
				Type:         SignalTypeCandidate,
				Data:         formatICECandidate(i, candidate, iceParams),
				ConnectionID: d.ConnectionID,
				NetworkID:    networkID,
			}); err != nil {
				return nil, fmt.Errorf("signal candidate: %w", err)
			}
		}

		select {
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
			if signal.Type != SignalTypeAnswer {
				d.signalError(signaling, networkID, ErrorCodeIncomingConnectionIgnored)
				return nil, fmt.Errorf("received signal for non-answer: %s", signal.String())
			}

			s := &sdp.SessionDescription{}
			if err := s.UnmarshalString(signal.Data); err != nil {
				d.signalError(signaling, networkID, ErrorCodeFailedToSetRemoteDescription)
				return nil, fmt.Errorf("decode answer: %w", err)
			}
			desc, err := parseDescription(s)
			if err != nil {
				d.signalError(signaling, networkID, ErrorCodeFailedToSetRemoteDescription)
				return nil, fmt.Errorf("parse offer: %w", err)
			}

			c := newConn(ice, dtls, sctp, d.ConnectionID, networkID, Addr{
				NetworkID:    signaling.NetworkID(),
				ConnectionID: d.ConnectionID,
				Candidates:   candidates,
			}, dialerConn{
				Dialer: d,
				stop:   stop,
			})
			defer func() {
				if err != nil {
					_ = c.Close()
				}
			}()
			go d.handleConn(ctx, c, signals)

			select {
			case <-ctx.Done():
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					d.signalError(signaling, networkID, ErrorCodeInactivityTimeout)
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
				c.handleTransports()
				return c, nil
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

// handleClose stops receiving notifications in Notifier from Signaling for incoming signals and errors.
func (d dialerConn) handleClose(*Conn) {
	d.stop()
}

// log returns the Log of the Dialer and extends it for a Conn with an additional [slog.Attr] of 'src'
// set to 'dialer' to mark that the Conn has been negotiated by Dialer. [Dialer.Log] will always be
// non-nil as it is always set up to the default [slog.Logger] before creating a Conn through newConn.
func (d dialerConn) log() *slog.Logger {
	return d.Log.With(slog.String("src", "dialer"))
}

// signalError signals a Signal of SignalTypeError into the remote connection using the
// [Signaling] implementation with the remote network ID and the code of the error
// occurred.
func (d Dialer) signalError(signaling Signaling, networkID string, code int) {
	_ = signaling.Signal(context.Background(), &Signal{
		Type:         SignalTypeError,
		Data:         strconv.Itoa(code),
		ConnectionID: d.ConnectionID,
		NetworkID:    networkID,
	})
}

// startTransports establishes ICE transport as [webrtc.ICERoleControlling], DTLS transport as
// [webrtc.DTLSRoleClient], and SCTP transport using the parameters included in the remote description.
// Once SCTP transport has established, it will create two data channels labeled 'ReliableDataChannel'
// and 'UnreliableDataChannel'. All methods are called with awareness of the [context.Context].
func (d Dialer) startTransports(ctx context.Context, conn *Conn, desc *description) error {
	conn.log.Debug("starting ICE transport as controller")
	iceRole := webrtc.ICERoleControlling
	if err := withContextCancel(ctx, func() error {
		return conn.ice.Start(nil, desc.ice, &iceRole)
	}, func() {
		_ = conn.ice.Stop()
	}); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}

	conn.log.Debug("starting DTLS transport as client")
	if err := withContextCancel(ctx, func() error {
		return conn.dtls.Start(desc.dtls)
	}, func() {
		_ = conn.dtls.Stop()
	}); err != nil {
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
		conn.channels[r] = wrapDataChannel(c, r)
	}
	return nil
}

// handleConn handles incoming Signals signaled from the remote connection and calls Conn.handleSignal
// to handle them within the Conn. The [context.Context] is used to return immediately when it has been
// canceled or exceeded the deadline.
func (d Dialer) handleConn(ctx context.Context, conn *Conn, signals <-chan *Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-conn.closed:
			return
		case signal, ok := <-signals:
			if !ok {
				// Signals channel closed, connection should be closed as well
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
	var (
		signals     = make(chan *Signal)
		filtered    = make(chan *Signal)
		ctx, cancel = context.WithCancel(context.Background())
	)
	stop := signaling.Notify(signals)
	var once sync.Once

	go func() {
		defer close(filtered)
		for {
			select {
			case <-ctx.Done():
				return
			case signal, ok := <-signals:
				if !ok {
					return
				}
				if signal.NetworkID != networkID || signal.ConnectionID != d.ConnectionID {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case filtered <- signal:
				}
			}
		}
	}()
	return filtered, func() {
		once.Do(func() {
			stop()
			cancel()
		})
	}
}
