package nethernet

import (
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
// The Conn do not utilize [webrtc.PeerConnection] as it does not allow creating a [sdp.SessionDescription]
// with custom.
//
// Once established and negotiated through either Dialer or Listener, Conn handles messages sent
// over the 'ReliableDataChannel' (which may be read using Read or ReadPacket), and ensures closure
// of its WebRTC transports to confirm that all transports within Conn are closed.
type Conn struct {
	ice  *webrtc.ICETransport
	dtls *webrtc.DTLSTransport
	sctp *webrtc.SCTPTransport

	// candidateReceived notifies that the first candidate is received from the other
	// end, indicating that the Conn is ready to start its transports.
	candidateReceived chan struct{}

	// candidates includes all [webrtc.ICECandidate] signaled from the remote connection.
	// New candidates are appended atomically to the slice.
	candidates   []webrtc.ICECandidate
	candidatesMu sync.Mutex // Guards candidates

	// negotiator is either Listener or Dialer that the Conn has been negotiated through.
	negotiator negotiator

	// channels contains *dataChannel used for sending messages in multiple MessageReliability.
	//
	// There is currently two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel'
	// that are expected to both open during negotiating a new Conn.
	channels [messageReliabilityCapacity]*dataChannel

	once   sync.Once     // Ensures closure occur only once
	closed chan struct{} // Notifies that a Conn has been closed.

	log *slog.Logger

	local     Addr
	id        uint64
	networkID string
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
	select {
	case <-conn.closed:
		return nil, net.ErrClosed
	case pk := <-conn.channels[r].packets:
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
	case <-conn.closed:
		return 0, net.ErrClosed
	default:
		if reliability == MessageReliabilityUnreliable && len(data) > maxMessageSize {
			return 0, fmt.Errorf("data larger than %d (received: %d) cannot be sent over UnreliableDataChannel", maxMessageSize, len(data))
		}
		d := conn.channels[reliability]

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

// Latency returns the current latency to the remote connection as half the round trip time (RTT)
// from the selected ICE candidate pair. If no candidate pair is selected or statistics are
// unavailable, it returns 0.
func (conn *Conn) Latency() time.Duration {
	stats, ok := conn.ice.GetSelectedCandidatePairStats()
	if !ok || stats.CurrentRoundTripTime == 0 {
		return 0
	}
	return time.Duration(stats.CurrentRoundTripTime*float64(time.Second)) / 2
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
	addr := conn.local
	addr.ConnectionID = conn.id
	pair, _ := conn.ice.GetSelectedCandidatePair()
	if pair != nil {
		addr.SelectedCandidate = pair.Local
	}
	return &addr
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

// Close closes the 'ReliableDataChannel' and 'UnreliableDataChannel', then closes the SCTP, DTLS,
// and ICE transports of the Conn. An error may be returned using [errors.Join], which contains
// non-nil errors encountered during closure.
func (conn *Conn) Close() (err error) {
	conn.once.Do(func() {
		close(conn.closed)
		conn.negotiator.handleClose(conn)

		for r := range messageReliabilityCapacity {
			if conn.channels[r] != nil {
				err = errors.Join(err, conn.channels[r].Close())
			}
		}

		err = errors.Join(
			err,
			conn.sctp.Stop(),
			conn.dtls.Stop(),
			conn.ice.Stop(),
		)
	})
	return err
}

// handleTransports handles incoming messages from the 'ReliableDataChannel' and ensures
// closure of its two data channels, as well as ICE, DTLS, and SCTP transports when any of
// them are closed by the remote connection.
func (conn *Conn) handleTransports() {
	for r := MessageReliability(0); r < messageReliabilityCapacity; r++ {
		ch := conn.channels[r]
		ch.OnMessage(func(msg webrtc.DataChannelMessage) {
			if err := ch.handleMessage(msg.Data); err != nil {
				if errors.Is(err, net.ErrClosed) {
					conn.log.Debug("message dropped due to closure of data channel",
						slog.String("label", ch.Label()))
					return
				}
				conn.log.Error("error handling remote message",
					slog.String("label", ch.Label()),
					slog.Any("error", err),
				)
			}
		})
		ch.OnClose(func() {
			_ = conn.Close()
		})
	}

	conn.sctp.OnDataChannelOpened(func(channel *webrtc.DataChannel) {
		conn.log.Error("connection was not expected to open a data channel after connection it is fully established", slog.String("label", channel.Label()))
		_ = conn.Close()
	})

	conn.ice.OnConnectionStateChange(func(state webrtc.ICETransportState) {
		switch state {
		case webrtc.ICETransportStateClosed, webrtc.ICETransportStateDisconnected, webrtc.ICETransportStateFailed:
			// This handler function itself is holding the lock, call Close in a goroutine.
			go conn.Close() // We need to make sure that all transports has been closed
		default:
		}
	})
	conn.dtls.OnStateChange(func(state webrtc.DTLSTransportState) {
		switch state {
		case webrtc.DTLSTransportStateClosed, webrtc.DTLSTransportStateFailed:
			// This handler function itself is holding the lock, call Close in a goroutine.
			go conn.Close() // We need to make sure that all transports has been closed
		default:
		}
	})
	conn.sctp.OnClose(func(err error) {
		// This handler function itself is holding the lock, call Close in a goroutine.
		go conn.Close() // We need to make sure that all transports has been closed
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
		candidate, err := ice.UnmarshalCandidate(signal.Data)
		if err != nil {
			return fmt.Errorf("decode candidate: %w", err)
		}
		protocol, err := webrtc.NewICEProtocol(candidate.NetworkType().NetworkShort())
		if err != nil {
			return fmt.Errorf("parse ICE protocol: %w", err)
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

		if err := conn.ice.AddRemoteCandidate(&i); err != nil {
			return fmt.Errorf("add remote candidate: %w", err)
		}

		conn.candidatesMu.Lock()
		if len(conn.candidates) == 0 {
			close(conn.candidateReceived)
		}
		conn.candidates = append(conn.candidates, i)
		conn.candidatesMu.Unlock()
	case SignalTypeError:
		code, err := strconv.ParseUint(signal.Data, 10, 32)
		if err != nil {
			return fmt.Errorf("parse error code: %w", err)
		}
		conn.log.Error("connection failed with error", slog.Uint64("code", code))
		if err := conn.Close(); err != nil {
			return fmt.Errorf("close: %w", err)
		}
	default:
		return fmt.Errorf("unknown signal type: %s", signal.Type)
	}
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
		return nil, errors.New("missing fingerprint attribute")
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
	case sdp.ConnectionRoleActpass.String():
		role = webrtc.DTLSRoleServer
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
	}, nil
}

// description contains parameters necessary for starting ICE, DTLS, and SCTP transport within a Conn.
//
// It may be created by parsing a [sdp.SessionDescription] signaled from a remote connection or filed
// in to encode a local description.
//
// A description may be parsed by a negotiator (Listener r Dialer) using parseDescription with a [sdp.SessionDescription]
// parsed from a Signal of SignalTypeOffer or SignalTypeAnswer.
type description struct {
	ice  webrtc.ICEParameters
	dtls webrtc.DTLSParameters
	sctp webrtc.SCTPCapabilities
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

	return d.WithMedia(media).Marshal()
}

// connectionRole returns a [sdp.ConnectionRole] indicating the local DTLS role. It is called
// by encode to include the role into the media description of local [sdp.SessionDescription]
// as a [sdp.Attribute] of 'setup'.
func (desc description) connectionRole(role webrtc.DTLSRole) sdp.ConnectionRole {
	switch role {
	case webrtc.DTLSRoleServer:
		return sdp.ConnectionRoleActpass
	default:
		return sdp.ConnectionRoleActive
	}
}

// newConn creates a Conn from the ICE, DTLS and SCTP transport associated with the IDs.
// The local Addr containing the local network ID will be used for returning local [net.Addr]
// of the Conn from [Conn.LocalAddr]. The implementation of negotiator may be used to obtain
// a [slog.Logger] of the Conn, and few other methods to handle events such as closures. The
// negotiator (caller) must establish each transport after creating a Conn when a first ICE
// candidate has been signaled from the remote connection.
func newConn(ice *webrtc.ICETransport, dtls *webrtc.DTLSTransport, sctp *webrtc.SCTPTransport, id uint64, networkID string, local Addr, n negotiator) *Conn {
	return &Conn{
		ice:  ice,
		dtls: dtls,
		sctp: sctp,

		candidateReceived: make(chan struct{}),

		negotiator: n,

		closed: make(chan struct{}),

		log: n.log().With(slog.Group("connection",
			slog.Uint64("id", id),
			slog.String("networkID", networkID),
		)),

		local: local,

		id:        id,
		networkID: networkID,
	}
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
