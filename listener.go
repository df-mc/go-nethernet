package nethernet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"golang.org/x/crypto/ssh"
)

// ListenConfig encapsulates options for creating a new Listener through [ListenConfig.Listen].
// It allows customizing logging, WebRTC API settings, and contexts for negotiations.
type ListenConfig struct {
	// Log is used for logging messages at various levels. If nil, the default [slog.Logger] will be set from
	// [slog.Default]. Log will be extended when a Conn is being accepted by [Listener.Accept] with additional
	// attributes such as the connection ID and network ID, and will have a 'src' attribute set to 'listener'
	// to mark that the Conn has been negotiated by Listener.
	Log *slog.Logger

	// API specifies custom configuration for WebRTC transports and data channels. If nil, a new [webrtc.API] will
	// be set from [webrtc.NewAPI]. The [webrtc.SettingEngine] of the API should not allow detaching data channels,
	// as it requires additional steps on the Conn (which cannot be determined by the Conn).
	API *webrtc.API

	// ConnContext provides a [context.Context] for starting the ICE, DTLS, and SCTP transports of the Conn. If nil,
	// a default [context.Context] with 5 seconds timeout will be used. The parent [context.Context] may be used to
	// create a [context.Context] to be returned (likely using [context.WithCancel] or [context.WithTimeout]).
	//
	// It may be called concurrently for different connections.
	ConnContext func(parent context.Context, conn *Conn) (context.Context, context.CancelFunc)

	// NegotiationContext provides a [context.Context] for the negotiation. If nil, a default [context.Context]
	// with 5 seconds timeout will be used. The parent [context.Context] may be used to create a [context.Context]
	// to be returned (likely using [context.WithCancel] or [context.WithTimeout]). If the deadline of the context
	// is exceeded, a Signal of SignalTypeError with ErrorCodeNegotiationTimeoutWaitingForAccept will be signaled back.
	//
	// It may be called concurrently for different connections.
	NegotiationContext func(parent context.Context) (context.Context, context.CancelFunc)

	// IssueServerIdentity issues the identity presented to clients in SDP answers.
	// The returned identity is used to produce the server-side 'a=identity' attribute.
	// The token must contain the public key corresponding the [Identity.PrivateKey] in
	// its 'cpk' claim.
	//
	// If set to nil, it is replaced to a function that automatically generates a
	// temporary identity. Because the generated key is not saved, clients using
	// Trust On First Use (TOFU) may treat each server restart as a different identity.
	//
	// It may be called concurrently for different connections.
	IssueServerIdentity func(ctx context.Context) (*Identity, error)

	// VerifyClientToken verifies the token contained in a client's identity
	// assertion and returns the public key populated in its 'cpk' claim.
	// The returned public key is used to verify the fingerprint assertion
	// carried in the client offer's 'a=identity' attribute.
	//
	// If the returned public key is nil, it will be automatically extracted
	// from the JWT token's payload.
	//
	// Unlike identity tokens issued by servers, client tokens are issued by
	// Minecraft's authorization service and include additional information
	// such as gamertag and XUID.
	//
	// These claims may be used to implement allowlists or blocklists.
	// However, the same checks should also be enforced by the Minecraft protocol
	// layer, since a malicious client may present a different token that
	// is bound to the same public key.
	//
	// By default, this is set to a function that only extracts the public key
	// from the 'cpk' claim in the JWT token. It does not perform cryptographic
	// verification using the public keys exposed by Minecraft's authorization service,
	// as this library does not provide access to that endpoint.
	//
	// The default verifier only binds the SDP identity assertion to the public
	// key in the token. It is appropriate for Bedrock integrations only when the
	// Minecraft protocol layer also verifies the Login packet token and checks
	// that the same public key was used in its 'cpk' claim. Servers that rely on
	// NetherNet identity alone should provide a verifier that validates token
	// issuance.
	//
	// It may be called concurrently for different connections.
	VerifyClientToken func(ctx context.Context, token string) (*ecdsa.PublicKey, error)

	// AllowAnonymous determines whether SDP offers without an 'a=identity'
	// attribute are accepted.
	// When set to false, all incoming connections must provide a valid identity
	// assertion. When set to true, unauthenticated peers are allowed to connect.
	//
	// The zero value is false. Set this explicitly for offline/custom clients
	// that do not send identity assertions.
	//
	// This may be useful for implementing offline-mode servers, but it removes
	// the identity binding normally provided by NetherNet and may allow replay
	// attacks against upstream protocols. It should therefore only be enabled
	// in trusted environments.
	AllowAnonymous bool

	// ICEGatherPolicy limits which local ICE candidates are gathered for
	// accepted connections.
	//
	// It may be used to restrict connectivity to specific candidate types, such
	// as relayed candidates from TURN servers only.
	ICEGatherPolicy webrtc.ICEGatherPolicy

	// DisableTrickleICE disables trickle ICE for connection negotiation.
	//
	// When set to true, the listener waits for ICE gathering to complete and embeds
	// all local candidates in the answer SDP. Otherwise, candidates are signaled
	// incrementally as separate [SignalTypeCandidate] signals after the answer is
	// sent.
	//
	// This may slow connection establishment because the answer cannot be sent
	// until candidate gathering completes.
	//
	// This behavior can be seen on dedicated servers with the
	// 'nethernet-disable-trickle-ice' setting property set to 'true'.
	DisableTrickleICE bool
}

// Listen listens on the local network ID specified by the Signaling implementation. It returns a Listener
// that may be used to accept established connections from [Listener.Accept]. Signaling will be used to notify
// incoming Signals from remote connections.
func (conf ListenConfig) Listen(signaling Signaling) (*Listener, error) {
	if conf.Log == nil {
		conf.Log = slog.Default()
	}
	if conf.API == nil {
		conf.API = webrtc.NewAPI()
	}
	if conf.IssueServerIdentity == nil {
		conf.Log.Warn("generating a new private key for this listener. a TOFU (Trust on First Use) prompt may be surfaced to players on first join")
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate private key: %w", err)
		}
		if conf.Log.Enabled(context.Background(), slog.LevelDebug) {
			pub, err := ssh.NewPublicKey(privateKey.Public())
			if err != nil {
				return nil, fmt.Errorf("convert public key to SSH: %w", err)
			}
			conf.Log.Debug("newly generated a private key for this listener", "fingerprint", ssh.FingerprintSHA256(pub))
		}
		conf.IssueServerIdentity = func(ctx context.Context) (*Identity, error) {
			return GenerateServerIdentity(privateKey, "self")
		}
	}
	if conf.VerifyClientToken == nil {
		conf.VerifyClientToken = func(ctx context.Context, token string) (*ecdsa.PublicKey, error) {
			// We intentionally do not verify the JWT signature here and instead
			// delegate that to the Minecraft protocol layer. Bedrock listeners should
			// verify the GameServerToken included in the Login packet and ensure that
			// its 'cpk' claim contains the same public key.
			return claimPublicKey(token, false)
		}
	}

	networkID := signaling.NetworkID()
	id, err := strconv.ParseUint(networkID, 10, 64)
	if err != nil {
		id = rand.Uint64()
	}

	l := &Listener{
		conf:      conf,
		signaling: signaling,
		networkID: networkID,
		id:        id,

		incoming:     make(chan *Conn),
		negotiations: make(map[negotiationKey]*listenerNegotiator),
		sem:          make(chan struct{}, maxListenerNegotiations),

		closed: make(chan struct{}),
	}

	l.stop = signaling.Notify(l)
	go l.monitorSignaling()

	return l, nil
}

// Listener implements a NetherNet connection listener.
type Listener struct {
	conf ListenConfig

	signaling Signaling
	networkID string
	// id is the numerical identifier for the Listener.
	id uint64

	incoming chan *Conn

	// negotiations is a map where each key is the identifiers for the connection that is
	// being/or already negotiated in the Listener, and each value is a listenerNegotiator
	// which negotiates WebRTC peers with a remote network.
	negotiations map[negotiationKey]*listenerNegotiator
	// negotiationsMu guards negotiations from concurrent read/write access.
	negotiationsMu sync.RWMutex
	sem            chan struct{}

	// stop is a function called to stop notifying signals from [Signaling].
	stop func()
	// closed is a channel that is closed when the Listener is closed.
	closed chan struct{}
	// once ensures that the closure occurs only once.
	once sync.Once
}

// negotiationKey represents a key used for identifying a negotiation
// initiated by an offer signal.
type negotiationKey struct {
	// networkID identifies the remote network. Multiple connections
	// may contain the same ID if they're from the same network.
	networkID string
	// connectionID identifies the remote connection to be negotiated.
	// It is a randomly-generated value assigned by the client.
	connectionID uint64
}

// listenerNegotiator handles one offer in a goroutine through acceptance or
// failure, so local ICE gathering and user callbacks do not block other offers.
// Candidates are deferred until the Conn is published; remote errors cancel immediately.
type listenerNegotiator struct {
	key negotiationKey

	deferred []*Signal
	mu       sync.Mutex

	conn *Conn
	// finished is guarded by mu and marks completion of the offer and any failure reply.
	finished bool
	// closed cancels this negotiation when its connection or listener closes.
	closed chan struct{}
	once   sync.Once
	// remoteCanceled suppresses failure replies after the peer cancels negotiation.
	remoteCanceled atomic.Bool

	// Listener is the parent Listener that received the offer signal via NotifySignal.
	*Listener
}

const (
	// maxListenerNegotiations bounds offer goroutines through acceptance or failure delivery.
	maxListenerNegotiations = 64
	// maxPendingSignalsPerNegotiation bounds signals received before Conn publication.
	maxPendingSignalsPerNegotiation = 32
)

// handleSignal handles the given Signal received from the remote network.
// Candidates are deferred until the offer publishes its Conn.
// Valid remote errors cancel pending work or close the published Conn immediately.
func (n *listenerNegotiator) handleSignal(signal *Signal) bool {
	select {
	case <-n.closed:
		return false
	default:
	}
	switch signal.Type {
	case SignalTypeOffer:
		// A duplicate shares the original connection ID, so an error reply would
		// close the original peer. Reject it without sending a connection error.
		return false
	case SignalTypeError:
		n.mu.Lock()
		n.remoteCanceled.Store(true)
		conn := n.conn
		n.mu.Unlock()
		if conn != nil {
			if err := conn.handleSignal(signal); err != nil {
				conn.log.Error("error handling signal", "error", err)
				return false
			}
		} else {
			n.close()
		}
		return true
	case SignalTypeCandidate:
		n.mu.Lock()
		select {
		case <-n.closed:
			n.mu.Unlock()
			return false
		default:
		}
		if conn := n.conn; conn != nil {
			n.mu.Unlock()
			if conn.Context().Err() != nil {
				return false
			}
			if err := conn.handleSignal(signal); err != nil {
				conn.log.Error("error handling signal", "error", err)
				return false
			}
			return true
		}

		if len(n.deferred) >= maxPendingSignalsPerNegotiation {
			n.mu.Unlock()
			n.log().Error("could not defer signal")
			return false
		}
		n.deferred = append(n.deferred, signal)
		n.mu.Unlock()
		return true
	default:
		n.log().Error("unexpected signal type", "signal", signal, "connectionID", signal.ConnectionID, "networkID", signal.NetworkID)
		return false
	}
}

// negotiate holds one admission slot until acceptance or the failure reply completes.
func (n *listenerNegotiator) negotiate(offer *Signal) {
	defer n.finish()
	if err := n.handleOffer(offer); err != nil {
		n.close()
		n.reportError(err)
		if errors.Is(err, net.ErrClosed) {
			return
		}
		n.log().Error("error handling offer", "error", err, "networkID", n.key.networkID, "connectionID", n.key.connectionID)
		return
	}
}

// finish releases admission and removes a closed owner after its final reply.
// Open, accepted connections keep their owner for later signals.
func (n *listenerNegotiator) finish() {
	n.mu.Lock()
	n.finished = true
	closed := n.Context().Err() != nil
	n.mu.Unlock()
	if closed {
		n.unregister()
	}
	<-n.sem
}

// reportError sends a bounded error reply when err carries a signaling code.
func (n *listenerNegotiator) reportError(err error) {
	if n.remoteCanceled.Load() {
		return
	}
	var s *signalError
	if errors.As(err, &s) {
		n.signalError(s.code)
	}
}

// signalError sends an error reply from the offer goroutine under a separate timeout.
// Keeping its admission slot until delivery finishes bounds slow signaling work
// without dropping replies for offers the listener has already admitted.
func (n *listenerNegotiator) signalError(code int) {
	// The connection may already have closed; use the listener's lifetime.
	ctx, cancel := context.WithTimeout(n.Listener.Context(), SignalErrorTimeout)
	defer cancel()
	if err := n.signaling.Signal(ctx, &Signal{
		Type:         SignalTypeError,
		ConnectionID: n.key.connectionID,
		NetworkID:    n.key.networkID,
		Data:         strconv.Itoa(code),
	}); err != nil {
		n.conf.Log.Error("error signaling error", slog.Any("error", err))
	}
}

// Context is canceled when this connection owner or its listener closes.
func (n *listenerNegotiator) Context() context.Context {
	return listenerContext{n.closed}
}

// close cancels the owner once. Pending offers retain their key until finish,
// so a delayed failure reply cannot reach a replacement connection with that key.
func (n *listenerNegotiator) close() {
	n.once.Do(func() {
		close(n.closed)
		n.mu.Lock()
		n.deferred = nil
		finished := n.finished
		n.mu.Unlock()
		if finished {
			n.unregister()
		}
	})
}

// unregister removes this owner without disturbing a replacement using its key.
func (n *listenerNegotiator) unregister() {
	n.negotiationsMu.Lock()
	if n.negotiations[n.key] == n {
		delete(n.negotiations, n.key)
	}
	n.negotiationsMu.Unlock()
}

// handleOffer handles an incoming Signal of SignalTypeOffer. It parses the data of Signal into [sdp.SessionDescription]
// and transforms into remote description for later use in negotiation. An answer will be created from local parameters of
// each transport and signaled back to the remote connection referenced in the offer.
func (n *listenerNegotiator) handleOffer(signal *Signal) error {
	d := &sdp.SessionDescription{}
	if err := d.UnmarshalString(signal.Data); err != nil {
		return wrapSignalError(fmt.Errorf("decode offer: %w", err), ErrorCodeFailedToSetRemoteDescription)
	}
	desc, err := parseDescription(d)
	if err != nil {
		return wrapSignalError(fmt.Errorf("parse offer: %w", err), ErrorCodeFailedToSetRemoteDescription)
	}

	var (
		ctx    context.Context
		parent = n.Context()
	)
	if n.conf.NegotiationContext != nil {
		var cancel context.CancelFunc
		ctx, cancel = n.conf.NegotiationContext(parent)
		if ctx == nil {
			panic("nethernet: Listener: NegotiationContext returned nil")
		}
		defer cancel()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, time.Second*15)
		defer cancel()
	}
	credentials, err := n.signaling.Credentials(ctx)
	if err != nil {
		return wrapSignalError(fmt.Errorf("obtain credentials: %w", err), ErrorCodeSignalingTurnAuthFailed)
	}

	c, err := newConn(
		n.conf.API,
		gatherOptions(credentials, n.conf.ICEGatherPolicy),
		signal.ConnectionID,
		signal.NetworkID,
		n.networkID,
		n,
		ErrorCodeFailedToCreateAnswer,
	)
	if err != nil {
		return fmt.Errorf("create peer connection: %w", err)
	}
	established := false
	defer func() {
		if !established {
			_ = c.Close()
		}
	}()
	disableTrickleICE := shouldDisableTrickleICE(n.conf.DisableTrickleICE, n.signaling)
	if disableTrickleICE {
		c.description.candidates, err = c.gatherCandidates(ctx)
		if err != nil {
			return wrapSignalError(fmt.Errorf("gather local candidates: %w", err), ErrorCodeICE)
		}
	}
	for _, candidate := range desc.candidates {
		// Non-trickle ICE connection may include candidates in a single SDP.
		if err := c.addRemoteCandidate(candidate); err != nil {
			return wrapSignalError(fmt.Errorf("add inline candidate: %w", err), ErrorCodeFailedToSetRemoteDescription)
		}
	}
	c.description.dtls.Role = n.answererRole(desc.dtls.Role)

	if desc.identity != nil {
		publicKey, err := n.conf.VerifyClientToken(ctx, desc.identity.Assertion.Token)
		if err != nil {
			return wrapSignalError(fmt.Errorf("verify client token: %w", err), ErrorCodeIdentityNotAllowed)
		}
		if publicKey == nil {
			publicKey, err = claimPublicKey(desc.identity.Assertion.Token, false)
			if err != nil {
				return wrapSignalError(fmt.Errorf("claim public key: %w", err), ErrorCodeIdentityNotAllowed)
			}
		}
		if err := desc.identity.verify(desc, publicKey); err != nil {
			return wrapSignalError(fmt.Errorf("verify identity assertion: %w", err), ErrorCodeIdentityNotAllowed)
		}
		c.publicKey = publicKey
	} else if !n.conf.AllowAnonymous {
		n.conf.Log.Warn("rejecting anonymous identity because AllowAnonymous is false",
			slog.Uint64("connectionID", signal.ConnectionID),
			slog.String("networkID", signal.NetworkID),
		)
		return wrapSignalError(errors.New("nethernet: anonymous identity not allowed"), ErrorCodeIdentityNotAllowed)
	}
	identity, err := n.conf.IssueServerIdentity(ctx)
	if err != nil {
		return wrapSignalError(fmt.Errorf("issue server identity: %w", err), ErrorCodeFailedToCreateIdentityAssertion)
	}
	if err := identity.sign(c.description); err != nil {
		return wrapSignalError(fmt.Errorf("generate identity assertion: %w", err), ErrorCodeFailedToCreateIdentityAssertion)
	}

	// Register a callback function immediately since the remote peer
	// may open data channels at any time while ICE candidates are being signaled.
	var (
		opened        atomic.Uint32
		channelsReady = make(chan struct{})
	)
	c.sctp.OnDataChannel(func(channel *webrtc.DataChannel) {
		for r := range messageReliabilityCapacity {
			if r.Valid(channel) {
				ch := wrapDataChannel(channel, r, c)
				if existing := c.storeChannel(r, ch); existing != nil {
					go c.close(fmt.Errorf("data channel created for same reliability parameters: %q", r.Parameters().Label))
					return
				}
				channel.OnOpen(sync.OnceFunc(func() {
					// If all data channels have been opened by remote peer, we can signal that the connection is ready.
					if opened.Add(1) == uint32(messageReliabilityCapacity) {
						close(channelsReady)
					}
				}))
				return
			}
		}
		go c.close(fmt.Errorf("invalid data channel opened: %q", channel.Label()))
	})

	// Encode an answer using the local parameters!
	answer, err := c.description.encode()
	if err != nil {
		return wrapSignalError(fmt.Errorf("encode answer: %w", err), ErrorCodeFailedToCreateAnswer)
	}

	if err := n.signaling.Signal(ctx, &Signal{
		Type:         SignalTypeAnswer,
		ConnectionID: signal.ConnectionID,
		Data:         string(answer),
		NetworkID:    signal.NetworkID,
	}); err != nil {
		// I don't think the error code will be signaled back to the remote connection, but just in case.
		return wrapSignalError(fmt.Errorf("signal answer: %w", err), ErrorCodeSignalingFailedToSend)
	}

	if !disableTrickleICE {
		if err := c.trickleCandidates(n.signaling); err != nil {
			return wrapSignalError(fmt.Errorf("start gathering local candidates: %w", err), ErrorCodeFailedToCreatePeerConnection)
		}
	}

	n.mu.Lock()
	select {
	case <-n.closed:
		n.mu.Unlock()
		return net.ErrClosed
	default:
	}
	// A remote error may have claimed cancellation before close acquires the lock.
	if n.remoteCanceled.Load() {
		n.mu.Unlock()
		return net.ErrClosed
	}
	n.conn = c
	deferred := n.deferred
	n.deferred = nil
	n.mu.Unlock()

	for _, deferredSignal := range deferred {
		n.handleSignal(deferredSignal)
	}

	if err := n.finaliseConn(c, desc, channelsReady); err != nil {
		return err
	}
	established = true
	return nil
}

// answererRole returns the local [webrtc.DTLSRole] for an answer based on the
// role signaled by the remote peer. If the remote peer uses
// [webrtc.DTLSRoleAuto], it will be [webrtc.DTLSRoleClient] since the ICE
// transport will always start as controlled.
func (n *listenerNegotiator) answererRole(role webrtc.DTLSRole) webrtc.DTLSRole {
	switch role {
	case webrtc.DTLSRoleServer:
		return webrtc.DTLSRoleClient
	case webrtc.DTLSRoleClient:
		return webrtc.DTLSRoleServer
	default:
		return webrtc.DTLSRoleClient
	}
}

// handleClose deletes the Conn from the Listener, since it is closed and can no longer be negotiated.
func (n *listenerNegotiator) handleClose(*Conn) {
	n.close()
}

// log extends the [slog.Logger] from [ListenConfig.Log] with an additional [slog.Attr] of "src" with the
// value "listener" to mark that the Conn has been negotiated by Listener, and returns it to be used as the logger
// of a Conn.
func (n *listenerNegotiator) log() *slog.Logger {
	return n.conf.Log.With(
		slog.String("src", "listener"),
		slog.String("networkID", n.key.networkID),
		slog.Uint64("connectionID", n.key.connectionID),
	)
}

// finaliseConn finalises the Conn. Once an ICE candidate for the Conn has been signaled from the remote
// connection, it starts the transports of the Conn using the remote description and a [context.Context]
// returned from [ListenConfig.ConnContext].
func (n *listenerNegotiator) finaliseConn(conn *Conn, d *description, channelsReady <-chan struct{}) (err error) {
	var (
		ctx    context.Context
		parent = n.Context()
	)
	if n.conf.ConnContext != nil {
		var cancel context.CancelFunc
		ctx, cancel = n.conf.ConnContext(parent, conn)
		if ctx == nil {
			panic("nethernet: ConnContext returned nil")
		}
		defer cancel()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, time.Second*5)
		defer cancel()
	}

	defer func() {
		if err != nil {
			switch err {
			case context.Canceled, context.DeadlineExceeded, net.ErrClosed:
				if cause := context.Cause(conn.ctx); cause != nil {
					err = cause
				}
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// Report the timeout through negotiate, which owns the error reply.
				err = &signalError{code: ErrorCodeNegotiationTimeoutWaitingForAccept, underlying: err}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-n.closed:
		return net.ErrClosed
	case <-conn.ctx.Done():
		return context.Cause(conn.ctx)
	case <-conn.candidateReceived:
		conn.log.Debug("received first candidate")
		if err := n.startTransports(ctx, conn, d, channelsReady); err != nil {
			return fmt.Errorf("start transports: %w", err)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-conn.ctx.Done():
			return context.Cause(conn.ctx)
		case <-n.closed:
			return net.ErrClosed
		case n.incoming <- conn:
		}
		return nil
	}
}

// startTransports starts ICE as [webrtc.ICERoleControlled], then starts DTLS
// and SCTP using the remote description. It blocks until the remote peer has
// created both 'ReliableDataChannel' and 'UnreliableDataChannel'. The provided
// [context.Context] is used to control the deadline.
func (n *listenerNegotiator) startTransports(ctx context.Context, conn *Conn, d *description, channelsReady <-chan struct{}) error {
	conn.log.Debug("starting ICE transport as controlled")
	iceRole := webrtc.ICERoleControlled
	if err := conn.ice.StartContext(ctx, nil, d.ice, &iceRole); err != nil {
		return fmt.Errorf("start ICE: %w", err)
	}

	conn.log.Debug("starting DTLS transport", slog.String("remoteRole", d.dtls.Role.String()))
	if err := conn.dtls.StartContext(ctx, d.dtls); err != nil {
		return fmt.Errorf("start DTLS: %w", err)
	}

	conn.log.Debug("starting SCTP transport")
	if err := withContextCancel(ctx, func() error {
		return conn.sctp.Start(d.sctp)
	}, func() {
		_ = conn.sctp.Stop()
	}); err != nil {
		return fmt.Errorf("start SCTP: %w", err)
	}
	conn.maxSegmentPayload.Store(conn.sctp.GetCapabilities().MaxMessageSize - 1)

	return n.waitForChannelsReady(ctx, conn, channelsReady)
}

// waitForChannelsReady blocks until all data channels have been opened by the
// remote peer, or until the Listener, Conn, or context is closed.
func (n *listenerNegotiator) waitForChannelsReady(ctx context.Context, conn *Conn, channelsReady <-chan struct{}) error {
	select {
	case <-n.closed:
	case <-channelsReady:
		return nil
	case <-conn.ctx.Done():
	case <-ctx.Done():
	}
	if err := context.Cause(conn.ctx); err != nil {
		return err
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	return net.ErrClosed
}

// Accept waits for and returns the next [Conn] to the Listener. An error may be
// returned, if the Listener has been closed.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case conn := <-l.incoming:
		return conn, nil
	}
}

// Addr returns an Addr that represents the local network ID of the Listener.
func (l *Listener) Addr() net.Addr {
	return &Addr{NetworkID: l.networkID}
}

// Context returns a context that is canceled when the Listener is closed.
func (l *Listener) Context() context.Context {
	return listenerContext{l.closed}
}

// Addr represents a network address that encapsulates both local and remote connection
// IDs and implements [net.Addr].
//
// The Addr provides details for the unique IDs of Conn and ICE Candidates used for establishing
// network connectivity.
type Addr struct {
	// ConnectionID is a unique ID assigned to a connection. It is generated by the client and
	// used in Signals signaled between clients and servers to uniquely reference a specific connection.
	ConnectionID uint64

	// NetworkID is a unique ID for the NetherNet network.
	NetworkID string

	// Candidates contains a list of ICE candidates. These candidates are either gathered locally or
	// signaled from a remote connection. ICE candidates are used to determine the UDP/TCP addresses
	// for establishing ICE transport and can be used to determine the network address of the connection.
	Candidates []webrtc.ICECandidate

	// SelectedCandidate is the candidate selected to connect with the ICE transport within a Conn.
	// An ICE candidate may be used to determine the UDP/TCP address of the connection. It may be nil
	// if the Conn has been closed, or if the Conn has encountered an error when obtaining the selected
	// ICE candidate pair.
	SelectedCandidate *webrtc.ICECandidate
}

// String formats the Addr as a string.
func (addr *Addr) String() string {
	b := &strings.Builder{}
	b.WriteString(addr.NetworkID)
	b.WriteByte(' ')
	if addr.ConnectionID != 0 {
		b.WriteByte('(')
		b.WriteString(strconv.FormatUint(addr.ConnectionID, 10))
		b.WriteByte(')')
	}
	if addr.SelectedCandidate != nil {
		b.WriteByte(' ')
		b.WriteByte('(')
		b.WriteString(addr.SelectedCandidate.String())
		b.WriteByte(')')
	}
	return b.String()
}

// Network returns the network type for the Addr, which is always 'nethernet'.
func (addr *Addr) Network() string { return "nethernet" }

// ID returns the network ID of Listener.
func (l *Listener) ID() int64 { return int64(l.id) }

// PongData is a stub.
func (l *Listener) PongData(b []byte) {
	l.signaling.PongData(b)
}

// NotifySignal handles an incoming Signal from the remote network and reports
// whether it was accepted for processing.
func (l *Listener) NotifySignal(signal *Signal) bool {
	if err := signal.validate(); err != nil {
		// This can happen when a Signaling implementation builds a Signal itself.
		l.conf.Log.Error("error validating signal", "error", err)
		return false
	}
	l.negotiationsMu.Lock()
	select {
	case <-l.Context().Done():
		l.negotiationsMu.Unlock()
		return false
	case <-l.signaling.Context().Done():
		l.negotiationsMu.Unlock()
		return false
	default:
		key := negotiationKey{
			networkID:    signal.NetworkID,
			connectionID: signal.ConnectionID,
		}

		n, ok := l.negotiations[key]
		if !ok {
			if signal.Type != SignalTypeOffer {
				l.conf.Log.Error("received non-offer signal for a non-existing negotiation", "signal", signal.String(), "networkID", signal.NetworkID)
				l.negotiationsMu.Unlock()
				return false
			}
			select {
			case l.sem <- struct{}{}:
				break
			default:
				l.conf.Log.Error("error allocating negotiation", "max", len(l.sem))
				l.negotiationsMu.Unlock()
				return false
			}
			n = &listenerNegotiator{
				key:      key,
				Listener: l,
				closed:   make(chan struct{}),
			}
			l.negotiations[key] = n
			go n.negotiate(signal)
			l.negotiationsMu.Unlock()
			return true
		}
		l.negotiationsMu.Unlock()

		return n.handleSignal(signal)
	}
}

// monitorSignaling closes the listener when its signaling connection ends.
func (l *Listener) monitorSignaling() {
	select {
	case <-l.closed:
		return
	case <-l.signaling.Context().Done():
		l.conf.Log.Warn("signaling context canceled", slog.Any("error", context.Cause(l.signaling.Context())))
		_ = l.Close()
	}
}

// withContextCancel calls f in a goroutine and returns early when ctx is done.
// If cancel is non-nil, it is called when ctx is done to help unblock f.
func withContextCancel(ctx context.Context, f func() error, cancel func()) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- f()
	}()
	select {
	case <-ctx.Done():
		if cancel != nil {
			cancel()
		}
		// Ensure the goroutine can complete without blocking even if it returns later.
		go func() { <-errCh }()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// Close closes the Listener, ensuring that any blocking methods will return [net.ErrClosed] as an error.
func (l *Listener) Close() error {
	l.once.Do(func() {
		l.negotiationsMu.Lock()
		close(l.closed)
		owners := make([]*listenerNegotiator, 0, len(l.negotiations))
		for _, n := range l.negotiations {
			owners = append(owners, n)
		}
		l.negotiationsMu.Unlock()
		for _, n := range owners {
			n.close()
		}
		l.stop()
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

// wrapSignalError returns a signalError that includes the error as its underlying error (which may be
// unwrapped with [errors.Unwrap]) and the code to be signaled back to the remote connection. It is typically
// called by methods handling incoming Signals on the Listener. Errors that already wrap a signalError
// are returned unchanged, preserving their original code and context.
func wrapSignalError(err error, code int) error {
	var existing *signalError
	if errors.As(err, &existing) {
		return err
	}
	return &signalError{code: code, underlying: err}
}

// listenerContext implements [context.Context] for a Listener.
type listenerContext struct{ closed <-chan struct{} }

// Deadline returns the zero [time.Time] and false, indicating that deadlines are not used.
func (listenerContext) Deadline() (zero time.Time, ok bool) {
	return zero, false
}

// Done returns a channel that is closed when the Listener has been closed.
func (ctx listenerContext) Done() <-chan struct{} {
	return ctx.closed
}

// Err returns [net.ErrClosed] if the Listener has been closed. Returns nil otherwise.
func (ctx listenerContext) Err() error {
	select {
	case <-ctx.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

// Value returns nil for any key, as no values are associated with the context.
func (listenerContext) Value(any) any {
	return nil
}
