package nethernet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
)

// Conn is an implementation of [net.Conn] for a peer connection between a specific remote
// NetherNet network/connection. Conn is safe for concurrent use by multiple goroutines except
// Read and ReadPacket.
//
// A Conn represents a WebRTC peer connection using ICE, DTLS, and SCTP transports and encapsulates
// two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel'. Most methods within
// Conn utilize the 'ReliableDataChannel', as the functionality of the 'UnreliableDataChannel' is less defined.
//
// A Conn may be established by dialing a remote network ID using [Dialer.DialContext] (and other aliases),
// or by accepting connections from a Listener that listens on a local network.
//
// Conn does not use [webrtc.PeerConnection], because it needs to build custom
// [sdp.SessionDescription] values during negotiation.
//
// Once established and negotiated through either Dialer or Listener, Conn handles messages sent
// over the 'ReliableDataChannel' (which may be read using Read or ReadPacket), and ensures closure
// of its WebRTC transports to confirm that all transports within Conn are closed.
type Conn struct {
	ice      *webrtc.ICETransport
	dtls     *webrtc.DTLSTransport
	sctp     *webrtc.SCTPTransport
	gatherer *webrtc.ICEGatherer

	// description is the local session description for the Conn.
	// newConn builds it from the local parameters of each underlying transport.
	description *description

	// candidateReceived notifies that the first candidate is received from the other
	// end, indicating that the Conn is ready to start its transports.
	candidateReceived chan struct{}

	// candidates includes all [webrtc.ICECandidate] signaled from the remote connection.
	// New candidates are appended atomically to the slice. It is guarded by candidatesMu.
	candidates []webrtc.ICECandidate
	// candidatesMu guards candidates from concurrent read-write access.
	candidatesMu sync.Mutex

	// negotiator is either Listener or Dialer that the Conn has been negotiated through.
	negotiator negotiator

	// channels contains *dataChannel used for sending messages in multiple MessageReliability.
	//
	// There is currently two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel'
	// that are expected to both open during negotiating a new Conn.
	channels [messageReliabilityCapacity]*dataChannel
	// channelsMu guards channels from concurrent read-write access during startup and closure.
	channelsMu sync.RWMutex

	// once ensures that the Conn is closed only once.
	once sync.Once

	log *slog.Logger

	// id is the random ID assigned to this connection.
	// It will appear in [Signal.ConnectionID].
	id uint64
	// networkID and localNetworkID are the IDs of the remote and local NetherNet networks.
	networkID, localNetworkID string

	// ctx is the background context associated with the Conn.
	ctx context.Context
	// cancel is the function used to cancel the ctx with a cause.
	// It is called by close and must not be called elsewhere.
	cancel context.CancelCauseFunc
}

// Read receives a message from the 'ReliableDataChannel'. The bytes of the message data are copied to
// the given data. An error may be returned if the Conn has been closed by [Conn.Close].
func (conn *Conn) Read(b []byte) (n int, err error) {
	pk, err := conn.Receive(MessageReliabilityReliable)
	if err != nil {
		return n, err
	}
	n = copy(b, pk)
	if n < len(pk) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

// Receive receives a packet in fully reconstructed state combined from multiple segments
// received from the data channel responsible for the MessageReliability. An error may be
// returned if the Conn has been closed by [Conn.Close].
func (conn *Conn) Receive(r MessageReliability) ([]byte, error) {
	if r >= messageReliabilityCapacity {
		return nil, fmt.Errorf("invalid message reliability: %d", r)
	}
	select {
	case <-conn.ctx.Done():
		return nil, context.Cause(conn.ctx)
	case pk := <-conn.channel(r).packets:
		return pk, nil
	}
}

// ReadPacket receives a message from the 'ReliableDataChannel' and returns the bytes. It is
// implemented for Minecraft read operations to avoid some bugs related to the Read method in
// their decoder.
func (conn *Conn) ReadPacket() ([]byte, error) {
	return conn.Receive(MessageReliabilityReliable)
}

// BatchHeader always returns a nil slice as no header is prefixed before packets.
func (conn *Conn) BatchHeader() []byte {
	return nil
}

// DisableEncryption always reports true as no encryption should be done on Minecraft connection.
// Disabling encryption is insecure and may allow attackers to replay Login packets.
// Servers should perform additional verification (for example, ensuring the player
// joined the Xbox Live multiplayer session) to confirm the client is legitimately
// authenticated.
func (conn *Conn) DisableEncryption() bool {
	return true
}

// Context returns the background context associated with the Conn.
// The returned context is canceled when the Conn is no longer usable.
// Its cancellation cause describes the reason the Conn was closed.
func (conn *Conn) Context() context.Context {
	return conn.ctx
}

// Write writes the data into the 'ReliableDataChannel'. If the data exceeds 10000 bytes, it is split into
// multiple segments. An error may be returned while writing a segment or if the Conn has been closed by [Conn.Close].
func (conn *Conn) Write(b []byte) (n int, err error) {
	return conn.Send(b, MessageReliabilityReliable)
}

// Send writes the data into the data channel responsible for the given MessageReliability.
// If the data exceeds 10,000 bytes, it is split into multiple segments. An error may be
// returned while writing one or more segments or the Conn has been closed by [Conn.Close].
func (conn *Conn) Send(data []byte, reliability MessageReliability) (n int, err error) {
	select {
	case <-conn.ctx.Done():
		return 0, context.Cause(conn.ctx)
	default:
		if reliability >= messageReliabilityCapacity {
			return 0, fmt.Errorf("invalid message reliability: %d", reliability)
		}
		if reliability == MessageReliabilityUnreliable && len(data) > maxMessageSize {
			return 0, fmt.Errorf("data larger than %d (received: %d) cannot be sent over UnreliableDataChannel", maxMessageSize, len(data))
		}
		d := conn.channel(reliability)

		// Hold the lock for the entire segmented write to prevent interleaving.
		d.write.Lock()
		defer d.write.Unlock()

		// Each segment is prefixed with a uint8 remaining-segment counter that starts
		// at totalSegments-1 and decrements to 0 for the final segment. This limits
		// the maximum number of segments to math.MaxUint8+1 (256).
		const maxSegments = math.MaxUint8 + 1
		totalSegments := (len(data) + maxMessageSize - 1) / maxMessageSize
		if totalSegments > maxSegments {
			return 0, fmt.Errorf("data too large: %d bytes requires %d segments (max %d)", len(data), totalSegments, maxSegments)
		}

		remaining := totalSegments - 1
		for i := 0; i < len(data); i += maxMessageSize {
			frag := data[i:min(len(data), i+maxMessageSize)]
			if err := d.Send(append([]byte{uint8(remaining)}, frag...)); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					err = net.ErrClosed
				}
				return n, fmt.Errorf("write segment #%d: %w", totalSegments-1-remaining, err)
			}
			n += len(frag)
			remaining--
		}
		return n, nil
	}
}

// Latency returns the current latency to the remote connection as half the Smoothed Round Trip Time (SRTT)
// from the statistics of the SCTP transport.
func (conn *Conn) Latency() time.Duration {
	return time.Duration(conn.sctp.Stats().SmoothedRoundTripTime*float64(time.Second)) / 2
}

// SetDeadline is a no-op implementation of [net.Conn.SetDeadline] and returns ErrUnsupported.
func (*Conn) SetDeadline(time.Time) error {
	return ErrUnsupported
}

// SetReadDeadline is a no-op implementation of [net.Conn.SetReadDeadline] and returns ErrUnsupported.
func (*Conn) SetReadDeadline(time.Time) error {
	return ErrUnsupported
}

// SetWriteDeadline is a no-op implementation of [net.Conn.SetWriteDeadline] and returns ErrUnsupported.
func (*Conn) SetWriteDeadline(time.Time) error {
	return ErrUnsupported
}

// LocalAddr returns an Addr that includes the local network ID of the Conn with locally-gathered
// ICE candidates.
func (conn *Conn) LocalAddr() net.Addr {
	addr := &Addr{
		NetworkID:    conn.localNetworkID,
		ConnectionID: conn.id,
	}
	pair, _ := conn.ice.GetSelectedCandidatePair()
	if pair != nil {
		addr.SelectedCandidate = pair.Local
	}
	candidates, err := conn.gatherer.GetLocalCandidates()
	if err == nil {
		addr.Candidates = candidates
	}
	return addr
}

// RemoteAddr returns an Addr that includes the remote network ID of the Conn with remotely-signaled
// ICE candidates. Candidates are atomically added when a Signal of type SignalTypeCandidate has been handled.
func (conn *Conn) RemoteAddr() net.Addr {
	addr := conn.remoteAddr()

	conn.candidatesMu.Lock()
	addr.Candidates = slices.Clone(conn.candidates)
	conn.candidatesMu.Unlock()

	pair, _ := conn.ice.GetSelectedCandidatePair()
	if pair != nil {
		addr.SelectedCandidate = pair.Remote
	}
	return addr
}

// remoteAddr returns a base Addr without ICE candidates signaled from the remote connection.
// It is used by [Conn.RemoteAddr] for returning the Addr with candidates and also by [Listener]
// for using Addr as the key for Conn.
func (conn *Conn) remoteAddr() *Addr {
	return &Addr{
		NetworkID:    conn.networkID,
		ConnectionID: conn.id,
	}
}

// close closes the data channels associated with reliability parameters, then closes each transport
// of the Conn. It also cancels the background context with the provided cause so that may be returned
// by current-blocking methods such as [Conn.Read].
func (conn *Conn) close(cause error) (err error) {
	conn.once.Do(func() {
		if cause != nil {
			conn.log.Debug("connection is closing with a cause", slog.Any("cause", cause))
		}
		conn.cancel(cause)
		conn.negotiator.handleClose(conn)

		for _, ch := range conn.snapshotChannels() {
			if ch != nil {
				err = errors.Join(err, ch.Close())
			}
		}

		err = errors.Join(
			err,
			conn.sctp.Stop(),
			conn.dtls.Stop(),
			conn.ice.Stop(),
			conn.gatherer.Close(),
		)
	})
	return err
}

// channel returns the dataChannel for the given MessageReliability.
func (conn *Conn) channel(r MessageReliability) *dataChannel {
	conn.channelsMu.RLock()
	defer conn.channelsMu.RUnlock()
	return conn.channels[r]
}

// storeChannel stores ch for the given MessageReliability if no channel has
// been stored yet. It returns the previously stored channel, or nil on success.
func (conn *Conn) storeChannel(r MessageReliability, ch *dataChannel) (existing *dataChannel) {
	conn.channelsMu.Lock()
	defer conn.channelsMu.Unlock()
	existing = conn.channels[r]
	if existing == nil {
		conn.channels[r] = ch
	}
	return existing
}

// snapshotChannels returns a copy of the channels array for safe iteration
// without holding the lock.
func (conn *Conn) snapshotChannels() [messageReliabilityCapacity]*dataChannel {
	conn.channelsMu.RLock()
	defer conn.channelsMu.RUnlock()
	return conn.channels
}

// Close closes the 'ReliableDataChannel' and 'UnreliableDataChannel', then closes the SCTP, DTLS,
// and ICE transports of the Conn. An error may be returned using [errors.Join], which contains
// non-nil errors encountered during closure.
func (conn *Conn) Close() (err error) {
	return conn.close(net.ErrClosed)
}

// handleTransports registers handlers for all underlying transports and data channels
// associated with the Conn. It also ensures that the Conn is closed if an unrecoverable
// error has occurred in any of the underlying transports and data channels.
func (conn *Conn) handleTransports() {
	conn.ice.OnConnectionStateChange(func(state webrtc.ICETransportState) {
		switch state {
		case webrtc.ICETransportStateClosed, webrtc.ICETransportStateDisconnected, webrtc.ICETransportStateFailed:
			// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
			go conn.close(fmt.Errorf("nethernet: ICE transport entered unrecoverable state: %s", state))
		default:
		}
	})
	conn.dtls.OnStateChange(func(state webrtc.DTLSTransportState) {
		switch state {
		case webrtc.DTLSTransportStateClosed, webrtc.DTLSTransportStateFailed:
			// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
			go conn.close(fmt.Errorf("nethernet: DTLS transport entered unrecoverable state: %s", state))
		default:
		}
	})
	conn.sctp.OnClose(func(err error) {
		var e error
		if err != nil {
			e = fmt.Errorf("nethernet: SCTP transport closed: %w", err)
		} else {
			e = errors.New("nethernet: SCTP transport closed")
		}
		// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
		go conn.close(e)
	})
}

// handleSignal handles an incoming Signal signaled from the remote connection.
//
// If the Signal is of SignalTypeCandidate, it parses a [webrtc.ICECandidate] from its data and
// adds it to the ICE transport of the Conn.
//
// If the Signal is of SignalTypeError, it closes the Conn immediately.
func (conn *Conn) handleSignal(signal *Signal) error {
	switch signal.Type {
	case SignalTypeCandidate:
		candidate, err := parseRemoteCandidate(signal.Data)
		if err != nil {
			return err
		}
		if err := conn.addRemoteCandidate(candidate); err != nil {
			return err
		}
	case SignalTypeError:
		code, err := strconv.ParseUint(signal.Data, 10, 32)
		if err != nil {
			return fmt.Errorf("parse error code: %w", err)
		}
		if err := conn.close(fmt.Errorf("nethernet: remote peer notified connection failure (code: %d)", code)); err != nil {
			return fmt.Errorf("close: %w", err)
		}
	default:
		return fmt.Errorf("unknown signal type: %s", signal.Type)
	}
	return nil
}

// parseRemoteCandidate parses a raw ICE candidate string into a [webrtc.ICECandidate].
// It accepts formats with or without an "a=" prefix; [ice.UnmarshalCandidate] handles
// the "candidate:" prefix.
func parseRemoteCandidate(data string) (webrtc.ICECandidate, error) {
	s := strings.TrimSpace(data)
	s = strings.TrimPrefix(s, "a=")

	candidate, err := ice.UnmarshalCandidate(s)
	if err != nil {
		return webrtc.ICECandidate{}, fmt.Errorf("decode candidate: %w", err)
	}
	protocol, err := webrtc.NewICEProtocol(candidate.NetworkType().NetworkShort())
	if err != nil {
		return webrtc.ICECandidate{}, fmt.Errorf("parse ICE protocol: %w", err)
	}
	i := webrtc.ICECandidate{
		Foundation: candidate.Foundation(),
		Priority:   candidate.Priority(),
		Address:    candidate.Address(),
		Protocol:   protocol,
		Port:       uint16(candidate.Port()),
		Component:  candidate.Component(),
		Typ:        webrtc.ICECandidateType(candidate.Type()),
		TCPType:    candidate.TCPType().String(),
	}
	if r := candidate.RelatedAddress(); r != nil {
		i.RelatedAddress, i.RelatedPort = r.Address, uint16(r.Port)
	}
	return i, nil
}

// addRemoteCandidate adds an ICE candidate to the connection's ICE transport and
// tracks it in the candidates slice. It closes candidateReceived on the first
// candidate to signal that ICE gathering may proceed.
func (conn *Conn) addRemoteCandidate(candidate webrtc.ICECandidate) error {
	if err := conn.ice.AddRemoteCandidate(&candidate); err != nil {
		return fmt.Errorf("add remote candidate: %w", err)
	}

	conn.candidatesMu.Lock()
	defer conn.candidatesMu.Unlock()

	if len(conn.candidates) == 0 {
		close(conn.candidateReceived)
	}
	conn.candidates = append(conn.candidates, candidate)
	return nil
}

const maxMessageSize = 10000

// parseDescription parses a [sdp.SessionDescription] signaled from a remote connection.
// It transforms the fields of the [sdp.SessionDescription] into a description, which can be
// used to start ICE, DTLS, and SCTP transports for a Conn.
//
// The function ensures for required attributes: 'ice-ufrag', 'ice-pwd','fingerprint', 'setup'
// and 'max-message-size'. An error may be returned if any of these attributes are missing or invalid.
func parseDescription(d *sdp.SessionDescription) (*description, error) {
	if len(d.MediaDescriptions) != 1 {
		return nil, fmt.Errorf("unexpected number of media descriptions: %d, expected 1", len(d.MediaDescriptions))
	}
	m := d.MediaDescriptions[0]

	ufrag, ok := m.Attribute("ice-ufrag")
	if !ok {
		return nil, errors.New("missing ice-ufrag attribute")
	}
	pwd, ok := m.Attribute("ice-pwd")
	if !ok {
		return nil, errors.New("missing ice-pwd attribute")
	}

	attr, ok := m.Attribute("fingerprint")
	if !ok {
		attr, ok = d.Attribute("fingerprint")
		if !ok {
			return nil, errors.New("missing fingerprint attribute")
		}
	}
	fingerprint := strings.Split(attr, " ")
	if len(fingerprint) != 2 {
		return nil, fmt.Errorf("invalid fingerprint: %s", attr)
	}
	fingerprintAlgorithm, fingerprintValue := fingerprint[0], fingerprint[1]

	attr, ok = m.Attribute("setup")
	if !ok {
		return nil, errors.New("missing setup attribute")
	}
	var role webrtc.DTLSRole
	switch attr {
	case sdp.ConnectionRoleActive.String():
		role = webrtc.DTLSRoleClient
	case sdp.ConnectionRolePassive.String():
		role = webrtc.DTLSRoleServer
	case sdp.ConnectionRoleActpass.String():
		role = webrtc.DTLSRoleAuto
	default:
		return nil, fmt.Errorf("invalid setup attribute: %s", attr)
	}

	attr, ok = m.Attribute("max-message-size")
	if !ok {
		return nil, errors.New("missing max-message-size attribute")
	}
	maxMessageSize, err := strconv.ParseUint(attr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse max-message-size attribute as uint32: %w", err)
	}

	var candidates []webrtc.ICECandidate
	for _, attr := range append(d.Attributes, m.Attributes...) {
		if !attr.IsICECandidate() {
			continue
		}
		candidate, err := parseRemoteCandidate(attr.Value)
		if err != nil {
			return nil, fmt.Errorf("parse remote candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}

	return &description{
		ice: webrtc.ICEParameters{
			UsernameFragment: ufrag,
			Password:         pwd,
		},
		dtls: webrtc.DTLSParameters{
			Role: role,
			Fingerprints: []webrtc.DTLSFingerprint{
				{
					Algorithm: fingerprintAlgorithm,
					Value:     fingerprintValue,
				},
			},
		},
		sctp: webrtc.SCTPCapabilities{
			MaxMessageSize: uint32(maxMessageSize),
		},
		candidates: candidates,
	}, nil
}

// gatherCandidates starts gathering local candidates and signaling them to the
// remote peer using the provided [Signaling] implementation.
func (conn *Conn) gatherCandidates(signaling Signaling) error {
	var candidateIndex atomic.Uint32
	conn.gatherer.OnLocalCandidate(func(candidate *webrtc.ICECandidate) {
		// ICEGatherer already tracks its internal state, so we don't need to check if the connection is closed.
		if candidate == nil {
			conn.log.Debug("completed gathering local candidates")
			return
		}
		ctx, cancel := context.WithTimeout(conn.Context(), time.Second*15)
		defer cancel()
		if err := signaling.Signal(ctx, &Signal{
			Type:         SignalTypeCandidate,
			ConnectionID: conn.id,
			Data:         formatICECandidate(int(candidateIndex.Add(1)), *candidate, conn.description.ice),
			NetworkID:    conn.networkID,
		}); err != nil {
			errCtx, cancel := context.WithTimeout(conn.Context(), time.Second*15)
			defer cancel()

			// I don't think the error code will be signaled back to the remote connection, but just in case.
			if err := signaling.Signal(errCtx, &Signal{
				Type:         SignalTypeError,
				ConnectionID: conn.id,
				Data:         strconv.Itoa(ErrorCodeSignalingFailedToSend),
				NetworkID:    conn.networkID,
			}); err != nil {
				conn.log.Error("error signaling error", slog.Any("error", err))
			}
			// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
			go conn.close(fmt.Errorf("signal candidate: %w", err))
		}
	})
	return conn.gatherer.Gather()
}

// description contains parameters necessary for starting ICE, DTLS, and SCTP transport within a Conn.
//
// It can be created either by parsing a remote [sdp.SessionDescription] or by
// filling it with local transport parameters before encoding.
//
// A negotiator (Listener or Dialer) uses parseDescription after decoding a
// SignalTypeOffer or SignalTypeAnswer payload into an [sdp.SessionDescription].
type description struct {
	ice  webrtc.ICEParameters
	dtls webrtc.DTLSParameters
	sctp webrtc.SCTPCapabilities

	// candidates are inline ICE candidates included as SDP attributes.
	candidates []webrtc.ICECandidate
}

// encode transforms the description into a [sdp.SessionDescription] and encodes them using the [sdp.SessionDescription.Marshal]
// method. It is called by a negotiator (Listener or Dialer) to signal an offer or answer to the remote connection with the local
// parameters of each transport within a Conn.
func (desc description) encode() ([]byte, error) {
	d := &sdp.SessionDescription{
		Version: 0x0,
		Origin: sdp.Origin{
			Username:       "-",
			SessionID:      rand.Uint64(),
			SessionVersion: 0x2,
			NetworkType:    "IN",
			AddressType:    "IP4",
			UnicastAddress: "127.0.0.1",
		},
		SessionName: "-",
		TimeDescriptions: []sdp.TimeDescription{
			{},
		},
		Attributes: []sdp.Attribute{
			{Key: sdp.AttrKeyGroup, Value: "BUNDLE 0"},
			sdp.NewPropertyAttribute(sdp.AttrKeyExtMapAllowMixed),
			{Key: sdp.AttrKeyMsidSemantic, Value: " WMS"},
		},
	}

	media := &sdp.MediaDescription{
		MediaName: sdp.MediaName{
			Media:   "application",
			Port:    sdp.RangedPort{Value: 9},
			Protos:  []string{"UDP", "DTLS", "SCTP"},
			Formats: []string{"webrtc-datachannel"},
		},
		ConnectionInformation: &sdp.ConnectionInformation{
			NetworkType: "IN",
			AddressType: "IP4",
			Address: &sdp.Address{
				Address: "0.0.0.0",
			},
		},
	}
	media.WithICECredentials(desc.ice.UsernameFragment, desc.ice.Password)
	media.WithValueAttribute("ice-options", "trickle")
	for _, fingerprint := range desc.dtls.Fingerprints {
		media.WithFingerprint(fingerprint.Algorithm, fingerprint.Value)
	}
	media.WithValueAttribute(sdp.AttrKeyConnectionSetup, desc.connectionRole(desc.dtls.Role).String())
	media.WithValueAttribute(sdp.AttrKeyMID, "0")
	media.WithValueAttribute("sctp-port", "5000")
	media.WithValueAttribute("max-message-size", strconv.FormatUint(uint64(desc.sctp.MaxMessageSize), 10))

	// We don't populate ICE candidates in the SDP but just in case.
	for _, candidate := range desc.candidates {
		d.Attributes = append(d.Attributes, sdp.Attribute{
			Key:   sdp.AttrKeyCandidate,
			Value: candidate.String(),
		})
	}

	return d.WithMedia(media).Marshal()
}

// connectionRole returns a [sdp.ConnectionRole] indicating the local DTLS role. It is called
// by encode to include the role into the media description of local [sdp.SessionDescription]
// as a [sdp.Attribute] of 'setup'.
func (desc description) connectionRole(role webrtc.DTLSRole) sdp.ConnectionRole {
	switch role {
	case webrtc.DTLSRoleClient:
		// The server will send ClientHello to the client.
		return sdp.ConnectionRoleActive
	case webrtc.DTLSRoleServer:
		// The client will send ClientHello to the server.
		return sdp.ConnectionRolePassive
	default:
		// The client asks the server to choose which role to initiate DTLS.
		return sdp.ConnectionRoleActpass
	}
}

// newConn creates a peer Conn using the provided [webrtc.API].
// It initiates the ICE, DTLS, and SCTP transports, and attaches callback
// handlers so the Conn closes if any transport enters an unrecoverable state.
//
// The caller must register [SCTPTransport.OnDataChannel] immediately on
// the returned Conn, then use [Conn.description] to signal an offer or
// answer to the remote peer.
func newConn(api *webrtc.API, credentials *Credentials, id uint64, networkID, localNetworkID string, n negotiator) (*Conn, error) {
	gatherer, err := api.NewICEGatherer(gatherOptions(credentials))
	if err != nil {
		return nil, wrapSignalError(fmt.Errorf("create ICE gatherer: %w", err), ErrorCodeFailedToCreatePeerConnection)
	}
	iceTransport := api.NewICETransport(gatherer)
	dtlsTransport, err := api.NewDTLSTransport(iceTransport, nil)
	if err != nil {
		return nil, wrapSignalError(fmt.Errorf("create DTLS transport: %w", err), ErrorCodeFailedToCreatePeerConnection)
	}
	sctpTransport := api.NewSCTPTransport(dtlsTransport)

	iceParams, err := iceTransport.GetLocalParameters()
	if err != nil {
		return nil, wrapSignalError(fmt.Errorf("obtain local ICE parameters: %w", err), ErrorCodeFailedToCreateAnswer)
	}
	dtlsParams, err := dtlsTransport.GetLocalParameters()
	if err != nil {
		return nil, wrapSignalError(fmt.Errorf("obtain local DTLS parameters: %w", err), ErrorCodeFailedToCreateAnswer)
	}
	if len(dtlsParams.Fingerprints) == 0 {
		return nil, wrapSignalError(errors.New("local DTLS parameters has no fingerprints"), ErrorCodeFailedToCreateAnswer)
	}
	sctpCapabilities := sctpTransport.GetCapabilities()

	c := &Conn{
		ice:      iceTransport,
		dtls:     dtlsTransport,
		sctp:     sctpTransport,
		gatherer: gatherer,

		description: &description{
			ice:  iceParams,
			dtls: dtlsParams,
			sctp: sctpCapabilities,
		},

		candidateReceived: make(chan struct{}),

		negotiator: n,

		log: n.log().With(slog.Group("connection",
			slog.Uint64("id", id),
			slog.String("networkID", networkID),
		)),

		id:             id,
		networkID:      networkID,
		localNetworkID: localNetworkID,
	}
	c.ctx, c.cancel = context.WithCancelCause(context.Background())
	c.handleTransports()
	return c, nil
}

type negotiator interface {
	// handleClose handles closure of the Conn. It is implemented for deleting closed
	// connections on Listener.
	handleClose(conn *Conn)
	// log returns a base [slog.Logger] to be used as the logger of Conn. It will be
	// extended when creating a Conn at newConn with additional attributes such as its
	// ID and network ID.
	log() *slog.Logger
}

var ErrUnsupported = errors.New("nethernet: unsupported")
