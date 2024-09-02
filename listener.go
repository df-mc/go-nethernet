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
	// Log is used to output several messages at many log levels. If left as nil, the
	// default [slog.Logger] will be set from [slog.Default].
	Log *slog.Logger

	// API specifies custom configuration for WebRTC transports, and data channels.
	API *webrtc.API

	ConnContext func(conn *Conn) context.Context
}

// Listen listens on the local network ID. The [Signaling] implementation is used to
// receive signals from the remote connections. A [Listener] will be returned, that is
// ready to accept established [Conn].
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
	signaling.Notify(l.closed, &listenerNotifier{l})
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

// Addr returns an Addr of network ID of [Listener].
func (l *Listener) Addr() net.Addr {
	return &Addr{NetworkID: l.networkID}
}

// Addr represents a [net.Addr] from the ConnectionID and NetworkID. It also includes
// a slice of remote Candidates signaled from the remote connection.
type Addr struct {
	ConnectionID uint64
	NetworkID    uint64
	Candidates   []webrtc.ICECandidate
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

// ID returns the network ID of [Listener].
func (l *Listener) ID() int64 { return int64(l.networkID) }

// PongData is a stub.
func (l *Listener) PongData([]byte) {}

type listenerNotifier struct{ *Listener }

func (l *listenerNotifier) NotifySignal(signal *Signal) {
	var err error
	switch signal.Type {
	case SignalTypeOffer:
		err = l.handleOffer(signal)
	case SignalTypeCandidate:
		err = l.handleCandidate(signal)
	case SignalTypeError:
		err = l.handleError(signal)
	default:
		l.conf.Log.Debug("received signal for unknown type", slog.Any("signal", signal))
		return
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

func (l *listenerNotifier) NotifyError(err error) {
	if !errors.Is(err, net.ErrClosed) {
		l.conf.Log.Error("notified error in signaling", internal.ErrAttr(err))
	}
	_ = l.Close()
}

// handleOffer handles an incoming Signal of SignalTypeOffer. An answer will be
// encoded and the listener will prepare a connection for handling the signals incoming that has the same ID.
func (l *Listener) handleOffer(signal *Signal) error {
	d := &sdp.SessionDescription{}
	if err := d.UnmarshalString(signal.Data); err != nil {
		return wrapSignalError(fmt.Errorf("decode offer: %w", err), ErrorCodeFailedToSetRemoteDescription)
	}
	desc, err := parseDescription(d)
	if err != nil {
		return wrapSignalError(fmt.Errorf("parse offer: %w", err), ErrorCodeFailedToSetRemoteDescription)
	}

	credentials, err := l.signaling.Credentials()
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
	case <-l.closed:
		return nil
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

		c := newConn(ice, dtls, sctp, desc, l.conf.Log, signal.ConnectionID, signal.NetworkID, l.networkID, candidates, l)

		l.connections.Store(signal.ConnectionID, c)
		go l.handleConn(c)

		return nil
	}
}

func (l *Listener) handleClose(conn *Conn) {
	l.connections.Delete(conn.id)
}

func (l *Listener) handleConn(conn *Conn) {
	var ctx context.Context
	if l.conf.ConnContext != nil {
		ctx = l.conf.ConnContext(conn)
		if ctx == nil {
			panic("nethernet: ConnContext returned nil")
		}
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
	}

	select {
	case <-l.closed:
		// Quit the goroutine when the listener closes.
		return
	case <-ctx.Done():
		return
	case <-conn.candidateReceived:
		conn.log.Debug("received first candidate")
		if err := l.startTransports(ctx, conn); err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				if err := l.signaling.Signal(&Signal{
					Type:         SignalTypeError,
					ConnectionID: conn.id,
					Data:         strconv.FormatUint(ErrorCodeInactivityTimeout, 10),
					NetworkID:    conn.networkID,
				}); err != nil {
					conn.log.Error("error signaling inactivity timeout", internal.ErrAttr(err))
				}
			}
			if !errors.Is(err, net.ErrClosed) {
				conn.log.Error("error starting transports", internal.ErrAttr(err))
			}
			return
		}
		conn.handleTransports()
		l.incoming <- conn
	}
}

// startTransports establishes ICE transport as [webrtc.ICERoleControlled], DTLS transport as [webrtc.DTLSRoleServer],
// and SCTP transport on the Conn. It will block until two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel'
// will be created by the remote connection.
func (l *Listener) startTransports(ctx context.Context, conn *Conn) error {
	conn.log.Debug("starting ICE transport as controlled")
	iceRole := webrtc.ICERoleControlled
	if err := withContext(ctx, func() error {
		return conn.ice.Start(nil, conn.remote.ice, &iceRole)
	}); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}

	conn.log.Debug("starting DTLS transport as server")
	if err := withContext(ctx, func() error {
		return conn.dtls.Start(conn.remote.dtls)
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
		return conn.sctp.Start(conn.remote.sctp)
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

// withContext calls f with context-aware (a little bit forcibly). This is useful for functions that does not
// accept any [context.Context] as a parameter of function, like Start method of each transport (that will mostly
// hang on some reason).
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

// handleCandidate handles an incoming Signal of SignalTypeCandidate. It looks up for a connection that has the same ID, and
// call the [Conn.handleSignal] method, which adds a remote candidate into its ICE transport.
func (l *Listener) handleCandidate(signal *Signal) error {
	conn, ok := l.connections.Load(signal.ConnectionID)
	if !ok {
		return fmt.Errorf("no connection found for ID %d", signal.ConnectionID)
	}
	return conn.(*Conn).handleSignal(signal)
}

// handleError handles an incoming Signal of SignalTypeError. It looks up for a connection that has the same ID, and
// call the [Conn.handleSignal] method, which parses the data into error code and closes the connection as failed.
func (l *Listener) handleError(signal *Signal) error {
	conn, ok := l.connections.Load(signal.ConnectionID)
	if !ok {
		return fmt.Errorf("no connection found for ID %d", signal.ConnectionID)
	}
	return conn.(*Conn).handleSignal(signal)
}

// Close closes the [Listener].
func (l *Listener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		close(l.incoming)
	})
	return nil
}

// signalError allows including an error code defined as constants of Signals with SignalTypeError.
// If returned during handling signals received from the remote connection, it also signals back a
// Signal of SignalTypeError with the code.
type signalError struct {
	code       uint32
	underlying error
}

func (e *signalError) Error() string {
	return fmt.Sprintf("nethernet: %s [signaling with code %d]", e.underlying, e.code)
}

func (e *signalError) Unwrap() error { return e.underlying }

// wrapSignalError returns a *signalError which includes the error as underlying (that is able to unwrap)
// and the code to be signaled back to the remote connection. It is mainly called by the methods to handle
// signals received from the remote connection on [Listener].
func wrapSignalError(err error, code uint32) *signalError {
	return &signalError{code: code, underlying: err}
}
