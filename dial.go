package nethernet

import (
	"context"
	"errors"
	"fmt"
	"github.com/df-mc/go-nethernet/internal"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"sync"
)

type Dialer struct {
	// NetworkID and ConnectionID are the local IDs of a Conn being established. If
	// left as zero, a random value will automatically set from rand.Uint64.
	NetworkID, ConnectionID uint64

	// Log is used to output several messages at many log levels. If left as nil, the default [slog.Logger]
	// will be set from [slog.Default]. It will be extended when returning a Conn with additional attributes
	// such as its ID and network ID, and a [slog.Attr] with the key "src" with the value "dialer" to mark
	// that the Conn has been negotiated by Dialer.
	Log *slog.Logger

	// API specifies custom configuration for WebRTC transports, and data channels. If left as nil, a new [webrtc.API]
	// will be set from [webrtc.NewAPI]. The webrtc.SettingEngine of the API should not allow detaching data channels
	// (by calling [webrtc.SettingEngine.DetachDataChannels]) as it requires additional steps on the Conn.
	API *webrtc.API
}

// DialContext establishes a Conn with a remote network with the ID. The implementation of [Signaling]
// may be used to signal an offer and local ICE candidates. It notifies Signals of SignalTypeAnswer and
// SignalTypeCandidate signaled from the remote connection. The [context.Context] may be used to cancel
// the connection as soon as possible. If [context.Context.Err] returns [context.DeadlineExceeded], it
// signals back a Signal of SignalTypeError with ErrorCodeInactivityTimeout or ErrorCodeNegotiationTimeoutWaitingForAccept
// based on the progress. A Conn may be returned, that is ready to receive and send packets.
func (d Dialer) DialContext(ctx context.Context, networkID uint64, signaling Signaling) (*Conn, error) {
	if d.NetworkID == 0 {
		d.NetworkID = rand.Uint64()
	}
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
		if err := signaling.Signal(&Signal{
			Type:         SignalTypeOffer,
			Data:         string(offer),
			ConnectionID: d.ConnectionID,
			NetworkID:    networkID,
		}); err != nil {
			return nil, fmt.Errorf("signal offer: %w", err)
		}
		for i, candidate := range candidates {
			if err := signaling.Signal(&Signal{
				Type:         SignalTypeCandidate,
				Data:         formatICECandidate(i, candidate, iceParams),
				ConnectionID: d.ConnectionID,
				NetworkID:    networkID,
			}); err != nil {
				return nil, fmt.Errorf("signal candidate: %w", err)
			}
		}

		n := d.notifySignals(ctx, networkID, signaling)
		select {
		case <-ctx.Done():
			if errors.Is(err, context.DeadlineExceeded) {
				d.signalError(signaling, networkID, ErrorCodeNegotiationTimeoutWaitingForResponse)
			}
			return nil, ctx.Err()
		case err := <-n.errs:
			return nil, fmt.Errorf("notified error from signaling: %w", err)
		case signal := <-n.signals:
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
				NetworkID:    d.NetworkID,
				ConnectionID: d.ConnectionID,
				Candidates:   candidates,
			}, d)
			go d.handleConn(ctx, c, n.signals)

			select {
			case <-ctx.Done():
				if errors.Is(err, context.DeadlineExceeded) {
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

// handleClose is a no-op method to implement negotiator.
func (Dialer) handleClose(*Conn) {}

// log returns Log of the Dialer. It will always be non-nil as it is always defaulted
// to the [slog.Logger] from [slog.Default] before creating a Conn.
func (d Dialer) log() *slog.Logger {
	return d.Log.With(slog.String("src", "dialer"))
}

// signalError signals a Signal of SignalTypeError into the remote connection using the
// [Signaling] implementation with the remote network ID and the code of the error
// occurred.
func (d Dialer) signalError(signaling Signaling, networkID uint64, code int) {
	_ = signaling.Signal(&Signal{
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
	if err := withContext(ctx, func() error {
		return conn.ice.Start(nil, desc.ice, &iceRole)
	}); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}

	conn.log.Debug("starting DTLS transport as client")
	if err := withContext(ctx, func() error {
		return conn.dtls.Start(desc.dtls)
	}); err != nil {
		return fmt.Errorf("start DTLS: %w", err)
	}

	conn.log.Debug("starting SCTP transport")
	if err := withContext(ctx, func() error {
		return conn.sctp.Start(desc.sctp)
	}); err != nil {
		return fmt.Errorf("start SCTP: %w", err)
	}
	if err := withContext(ctx, func() error {
		var err error
		conn.reliable, err = d.API.NewDataChannel(conn.sctp, &webrtc.DataChannelParameters{
			Label: "ReliableDataChannel",
		})
		return err
	}); err != nil {
		return fmt.Errorf("create ReliableDataChannel: %w", err)
	}
	if err := withContext(ctx, func() error {
		var err error
		conn.unreliable, err = d.API.NewDataChannel(conn.sctp, &webrtc.DataChannelParameters{
			Label:   "UnreliableDataChannel",
			Ordered: false,
		})
		return err
	}); err != nil {
		return fmt.Errorf("create UnreliableDataChannel: %w", err)
	}
	return nil
}

// handleConn handles incoming Signals signaled from the remote connection, and calls Conn.handleSignal
// to handle them in the Conn. The [context.Context] is used to return immediately when it has been
// canceled or exceeded the deadline.
func (d Dialer) handleConn(ctx context.Context, conn *Conn, signals <-chan *Signal) {
	for {
		select {
		case <-ctx.Done():
			return
		case signal := <-signals:
			switch signal.Type {
			case SignalTypeCandidate, SignalTypeError:
				if err := conn.handleSignal(signal); err != nil {
					conn.log.Error("error handling signal", internal.ErrAttr(err))
				}
			}
		}
	}
}

// notifySignals starts notifying incoming Signals that has the same network ID and [Dialer.ConnectionID]
// with dialerNotifier. The [context.Context] is used to cancel the notification.
func (d Dialer) notifySignals(ctx context.Context, networkID uint64, signaling Signaling) *dialerNotifier {
	n := &dialerNotifier{
		Dialer: d,

		signals:   make(chan *Signal),
		errs:      make(chan error),
		networkID: networkID,
	}
	signaling.Notify(ctx, n)
	return n
}

type dialerNotifier struct {
	Dialer

	signals chan *Signal // Notifies incoming Signal that has the same IDs
	errs    chan error   // Notifies error occurred in Signaling

	once      sync.Once
	networkID uint64
}

func (d *dialerNotifier) NotifySignal(signal *Signal) {
	if signal.ConnectionID != d.ConnectionID || signal.NetworkID != d.networkID {
		return
	}
	d.signals <- signal
}

func (d *dialerNotifier) NotifyError(err error) {
	d.errs <- err

	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		d.close()
	}
}

func (d *dialerNotifier) close() {
	d.once.Do(func() {
		close(d.signals)
		close(d.errs)
	})
}
