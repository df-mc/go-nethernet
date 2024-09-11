package nethernet

import (
	"context"
	"errors"
	"fmt"
	"github.com/df-mc/go-nethernet/internal"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ListenConfig struct {
	// Log is used to output several messages at many log levels. If left as nil, the default [slog.Logger]
	// will be set from [slog.Default]. It will be extended when a Conn is being accepted by [Listener.Accept]
	// with additional attributes such as its ID and network ID, and a [slog.Attr] with the key "src" with the
	// value "listener" to mark that the Conn has been negotiated by Listener.
	Log *slog.Logger

	// API specifies custom configuration for WebRTC transports, and data channels. If left as nil, a new
	// [webrtc.API] will be set from [webrtc.NewAPI]. The webrtc.SettingEngine of the API should not allow
	// detaching data channels (by calling [webrtc.SettingEngine.DetachDataChannels]) as it requires additional
	// steps on the Conn (which cannot be determined by the Conn to be enabled).
	API *webrtc.API

	// ConnContext returns a [context.Context] for the Conn, which may be used to start the ICE, DTLS and SCTP
	// transports of the Conn in Listener. The parent [context.Context] may be used to create a [context.Context]
	// to be returned (likely with [context.WithCancel] or [context.WithTimeout]) as the first parameter. If set
	// as nil, a [context.Context] with 5 seconds timeout will be used instead.
	ConnContext func(parent context.Context, conn *Conn) context.Context

	// NegotiationContext returns a [context.Context] for a negotiation, that may occur by notifying a Signal
	// of SignalTypeOffer in Listener. The parent [context.Context] may be used to create a [context.Context]
	// to be returned (likely with [context.WithCancel] or [context.WithTimeout]) as the first parameter. If
	// set as nil, a [context.Context] with 5 seconds timeout will be used instead. When the returned context
	// is done and [context.Context.Err] returns [context.DeadlineExceeded], it signals back a Signal of SignalTypeError
	// with ErrorCodeNegotiationTimeoutWaitingForAccept.
	NegotiationContext func(parent context.Context) context.Context
}

// Listen listens on a local network referenced on the ID and returns a Listener, that may be used to accept
// established Conn from [Listener.Accept]. The implementation of [Signaling] may be used to notify incoming
// Signals signaled from the remote connections.
func (conf ListenConfig) Listen(networkID uint64, signaling Signaling) (*Listener, error) {
	if conf.Log == nil {
		conf.Log = slog.Default()
	}
	if conf.API == nil {
		conf.API = webrtc.NewAPI()
	}
	l := &Listener{
		conf:      conf,
		signaling: signaling,
		networkID: networkID,

		incoming: make(chan *Conn),

		closed: make(chan struct{}),
	}
	signaling.Notify(l.context(), listenerNotifier{l})
	return l, nil
}

// Listener implements a NetherNet connection listener.
type Listener struct {
	conf ListenConfig

	signaling Signaling
	networkID uint64

	connections sync.Map

	incoming chan *Conn

	closed chan struct{}
	once   sync.Once
}

// Accept waits for and returns the next [Conn] to the listener. An error may be
// returned, if the listener has been closed.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.incoming:
		return conn, nil
	}
}

// Addr returns an Addr with the local network ID of Listener.
func (l *Listener) Addr() net.Addr {
	return &Addr{NetworkID: l.networkID}
}

// Addr represents a [net.Addr] from local or remote ConnectionID and NetworkID.
type Addr struct {
	// ConnectionID is a unique ID randomly generated first on the client. It is present in
	// Signals sent from both client/server to uniquely identify a Conn.
	ConnectionID uint64
	// NetworkID is a unique ID of the NetherNet network.
	NetworkID uint64
	// Candidates contains all ICE candidates either locally-gathered or remotely-signaled.
	// It can be used to determine the UDP/TCP address of the connection used to connect ICE
	// transport.
	Candidates []webrtc.ICECandidate
}

func (addr *Addr) String() string {
	b := &strings.Builder{}
	b.WriteString(strconv.FormatUint(addr.NetworkID, 10))
	b.WriteByte(' ')
	if addr.ConnectionID != 0 {
		b.WriteByte('(')
		b.WriteString(strconv.FormatUint(addr.ConnectionID, 10))
		b.WriteByte(')')
	}
	return b.String()
}

func (addr *Addr) Network() string { return "nethernet" }

// ID returns the network ID of Listener.
func (l *Listener) ID() int64 { return int64(l.networkID) }

// PongData is a stub.
func (l *Listener) PongData([]byte) {}

type listenerNotifier struct{ *Listener }

// NotifySignal notifies an incoming Signal to the Listener. It calls corresponding Listener
// methods for handling Signal of each type. If an signalError has been returned, it signals
// back SignalTypeError with the code of the error.
func (l listenerNotifier) NotifySignal(signal *Signal) {
	var err error
	switch signal.Type {
	case SignalTypeOffer:
		err = l.handleOffer(signal)
	default:
		err = l.handleSignal(signal)
	}
	if err != nil {
		var s *signalError
		if errors.As(err, &s) {
			if err := l.signaling.Signal(&Signal{
				Type:         SignalTypeError,
				ConnectionID: signal.ConnectionID,
				Data:         strconv.FormatUint(uint64(s.code), 10),
				NetworkID:    signal.NetworkID,
			}); err != nil {
				l.conf.Log.Error("error signaling error", internal.ErrAttr(err))
			}
		}
		l.conf.Log.Error("error handling signal", slog.Any("signal", signal), internal.ErrAttr(err))
	}
}

// NotifyError notifies the error occurred in the Signaling implementation and closes the Listener if the error is
// either [net.ErrClosed] or [context.DeadlineExceeded] or [context.Canceled] as no more incoming signals can be
// notified by the Listener.
func (l listenerNotifier) NotifyError(err error) {
	l.conf.Log.Error("notified error in signaling", internal.ErrAttr(err))
	if errors.Is(err, net.ErrClosed) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		_ = l.Close()
	}
}

// handleOffer handles an incoming Signal of SignalTypeOffer. It parses the data of Signal into [sdp.SessionDescription]
// and transforms into remote description for later use in negotiation. An answer will be encoded from local parameters
// of each transport and signaled back to the remote connection referenced in the offer.
func (l *Listener) handleOffer(signal *Signal) error {
	d := &sdp.SessionDescription{}
	if err := d.UnmarshalString(signal.Data); err != nil {
		return wrapSignalError(fmt.Errorf("decode offer: %w", err), ErrorCodeFailedToSetRemoteDescription)
	}
	desc, err := parseDescription(d)
	if err != nil {
		return wrapSignalError(fmt.Errorf("parse offer: %w", err), ErrorCodeFailedToSetRemoteDescription)
	}

	var ctx context.Context
	if l.conf.NegotiationContext != nil {
		if ctx = l.conf.NegotiationContext(l.context()); ctx == nil {
			panic("nethernet: Listener: NegotiationContext returned nil")
		}
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(l.context(), time.Second*15)
		defer cancel()
	}
	credentials, err := l.signaling.Credentials(ctx)
	if err != nil {
		return wrapSignalError(fmt.Errorf("obtain credentials: %w", err), ErrorCodeSignalingTurnAuthFailed)
	}
	gatherer, err := l.conf.API.NewICEGatherer(gatherOptions(credentials))
	if err != nil {
		return wrapSignalError(fmt.Errorf("create ICE gatherer: %w", err), ErrorCodeFailedToCreatePeerConnection)
	}

	var (
		// Local candidates gathered by webrtc.ICEGatherer
		candidates []webrtc.ICECandidate
		// Notifies that gathering for local candidates has finished.
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
		return wrapSignalError(fmt.Errorf("gather local candidates: %w", err), ErrorCodeFailedToCreatePeerConnection)
	}

	select {
	case <-ctx.Done():
		return wrapSignalError(fmt.Errorf("gather local candidates: %w", err), ErrorCodeFailedToCreatePeerConnection)
	case <-gatherFinished:
		ice := l.conf.API.NewICETransport(gatherer)
		dtls, err := l.conf.API.NewDTLSTransport(ice, nil)
		if err != nil {
			return wrapSignalError(fmt.Errorf("create DTLS transport: %w", err), ErrorCodeFailedToCreatePeerConnection)
		}
		sctp := l.conf.API.NewSCTPTransport(dtls)

		iceParams, err := ice.GetLocalParameters()
		if err != nil {
			return wrapSignalError(fmt.Errorf("obtain local ICE parameters: %w", err), ErrorCodeFailedToCreateAnswer)
		}
		dtlsParams, err := dtls.GetLocalParameters()
		if err != nil {
			return wrapSignalError(fmt.Errorf("obtain local DTLS parameters: %w", err), ErrorCodeFailedToCreateAnswer)
		}
		if len(dtlsParams.Fingerprints) == 0 {
			return wrapSignalError(errors.New("local DTLS parameters has no fingerprints"), ErrorCodeFailedToCreateAnswer)
		}
		sctpCapabilities := sctp.GetCapabilities()

		// Encode an answer using the local parameters!
		answer, err := description{
			ice:  iceParams,
			dtls: dtlsParams,
			sctp: sctpCapabilities,
		}.encode()
		if err != nil {
			return wrapSignalError(fmt.Errorf("encode answer: %w", err), ErrorCodeFailedToCreateAnswer)
		}

		if err := l.signaling.Signal(&Signal{
			Type:         SignalTypeAnswer,
			ConnectionID: signal.ConnectionID,
			Data:         string(answer),
			NetworkID:    signal.NetworkID,
		}); err != nil {
			// I don't think the error code will be signaled back to the remote connection, but just in case.
			return wrapSignalError(fmt.Errorf("signal answer: %w", err), ErrorCodeSignalingFailedToSend)
		}
		for i, candidate := range candidates {
			if err := l.signaling.Signal(&Signal{
				Type:         SignalTypeCandidate,
				ConnectionID: signal.ConnectionID,
				Data:         formatICECandidate(i, candidate, iceParams),
				NetworkID:    signal.NetworkID,
			}); err != nil {
				// I don't think the error code will be signaled back to the remote connection, but just in case.
				return wrapSignalError(fmt.Errorf("signal candidate: %w", err), ErrorCodeSignalingFailedToSend)
			}
		}

		c := newConn(ice, dtls, sctp, signal.ConnectionID, signal.NetworkID, Addr{
			NetworkID:  l.networkID,
			Candidates: candidates,
		}, l)

		l.connections.Store(c.remoteAddr().String(), c)
		go l.handleConn(c, desc)

		return nil
	}
}

// handleSignal lookups for a Conn with the same ID and network ID of the Signal, and notifies it to the Conn
// by calling Conn.handleSignal. It is used as a default switch of listenerNotifier.NotifySignal.
func (l *Listener) handleSignal(signal *Signal) error {
	addr := &Addr{
		ConnectionID: signal.ConnectionID,
		NetworkID:    signal.NetworkID,
	}
	conn, ok := l.connections.Load(addr.String())
	if !ok {
		return fmt.Errorf("no connection found for %s", addr)
	}
	return conn.(*Conn).handleSignal(signal)
}

// handleConn deletes the Conn from the Listener as it is closed and no longer can be negotiated
// on the Listener.
func (l *Listener) handleClose(conn *Conn) {
	l.connections.Delete(conn.remoteAddr().String())
}

// log extends the [slog.Logger] from [ListenConfig.Log] with an additional attribute with the key
// "src" and the value "listener" and returns it to be used as the logger of Conn.
func (l *Listener) log() *slog.Logger {
	return l.conf.Log.With(slog.String("src", "listener"))
}

// handleConn finalises the Conn. Once an ICE candidate for the Conn has been signaled from the remote
// connection, it starts the transports of the Conn using the remote description and a [context.Context]
// returned from [ListenConfig.ConnContext].
func (l *Listener) handleConn(conn *Conn, d *description) {
	var err error
	defer func() {
		if err != nil {
			l.connections.Delete(conn.remoteAddr().String()) // Stop notifying for the Conn.

			if errors.Is(err, context.DeadlineExceeded) {
				if err := l.signaling.Signal(&Signal{
					Type:         SignalTypeError,
					ConnectionID: conn.id,
					Data:         strconv.Itoa(ErrorCodeNegotiationTimeoutWaitingForAccept),
					NetworkID:    conn.networkID,
				}); err != nil {
					conn.log.Error("error signaling timeout", internal.ErrAttr(err))
				}
			}
			if !errors.Is(err, net.ErrClosed) {
				conn.log.Error("error starting transports", internal.ErrAttr(err))
			}
		}
	}()

	var ctx context.Context
	if l.conf.ConnContext != nil {
		ctx = l.conf.ConnContext(l.context(), conn)
		if ctx == nil {
			panic("nethernet: ConnContext returned nil")
		}
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(l.context(), time.Second*5)
		defer cancel()
	}

	select {
	case <-ctx.Done():
		err = ctx.Err()
	case <-conn.candidateReceived:
		conn.log.Debug("received first candidate")
		if err = l.startTransports(ctx, conn, d); err != nil {
			return
		}
		conn.handleTransports()
		l.incoming <- conn
	}
}

// context returns the [context.Context] of the Listener, which will be canceled when the Listener is closed.
// It is used to notify signals and as the parent of the [context.Context] used for negotiation.
func (l *Listener) context() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-l.closed
		cancel()
	}()
	return ctx
}

// startTransports establishes ICE transport as [webrtc.ICERoleControlled], DTLS transport as [webrtc.DTLSRoleServer]
// and SCTP transport using the remote description. It will block until two data channels labeled 'ReliableDataChannel'
// and 'UnreliableDataChannel' will be created by the remote connection. The [context.Context] is used to cancel blocking.
func (l *Listener) startTransports(ctx context.Context, conn *Conn, d *description) error {
	conn.log.Debug("starting ICE transport as controlled")
	iceRole := webrtc.ICERoleControlled
	if err := withContext(ctx, func() error {
		return conn.ice.Start(nil, d.ice, &iceRole)
	}); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}

	conn.log.Debug("starting DTLS transport as server")
	if err := withContext(ctx, func() error {
		return conn.dtls.Start(d.dtls)
	}); err != nil {
		return fmt.Errorf("start DTLS: %w", err)
	}

	conn.log.Debug("starting SCTP transport")
	var (
		once   = new(sync.Once)
		opened = make(chan struct{}, 1)
	)
	conn.sctp.OnDataChannelOpened(func(channel *webrtc.DataChannel) {
		switch channel.Label() {
		case "ReliableDataChannel":
			conn.reliable = channel
		case "UnreliableDataChannel":
			conn.unreliable = channel
		}
		if conn.reliable != nil && conn.unreliable != nil {
			once.Do(func() {
				close(opened)
			})
		}
	})
	if err := withContext(ctx, func() error {
		return conn.sctp.Start(d.sctp)
	}); err != nil {
		return fmt.Errorf("start SCTP: %w", err)
	}

	select {
	case <-l.closed:
		return net.ErrClosed
	case <-opened:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// withContext calls the function with context-awareness (a little bit forcibly). It is useful for functions that
// does not accept any [context.Context] as a parameter, like the Start method of each transport of the Conn (that
// will mostly hang if the remote connection does nothing).
func withContext(ctx context.Context, f func() error) error {
	err := make(chan error, 1)
	go func() {
		err <- f()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-err:
		return err
	}
}

// Close closes the Listener. Any blocking methods will return net.ErrClosed as an error.
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		close(l.incoming)
	})
	return nil
}

// A signalError may be returned by the methods of Listener to handle incoming Signals signaled from the
// remote connection. The listenerNotifier may signal back with SignalTypeError to notify the error code
// occurred during handling a Signal.
type signalError struct {
	// code is the code of the error occurred, it is one of constants defined in the below of SignalTypeError.
	code       int
	underlying error
}

func (e *signalError) Error() string {
	return fmt.Sprintf("nethernet: %s [signaling with code %d]", e.underlying, e.code)
}

// Unwrap returns the underlying error so that may be unwrapped with errors.Unwrap.
func (e *signalError) Unwrap() error { return e.underlying }

// wrapSignalError returns a signalError which includes the error as its underlying error (that may be
// unwrapped with errors.Unwrap) and the code to be signaled back to the remote connection. It is usually
// called by the methods to handle incoming Signals signaled from the remote connection on Listener.
func wrapSignalError(err error, code int) *signalError {
	return &signalError{code: code, underlying: err}
}
