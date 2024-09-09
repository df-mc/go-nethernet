package nethernet

import (
	"errors"
	"fmt"
	"github.com/df-mc/go-nethernet/internal"
	"github.com/pion/ice/v4"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v4"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Conn is an implementation of [net.Conn] interface for a peer connection between
// a specific remote NetherNet network/connection. Conn is safe to use with concurrent
// goroutines.
//
// A Conn is a WebRTC peer connection established with ICE, DTLS and SCTP transport, and
// has two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel', most of
// the methods implemented in Conn uses 'ReliableDataChannel' as it is unclear how 'UnreliableDataChannel'
// works.
//
// A Conn may be established with a remote network ID using [Dialer.DialContext] and other aliases.
// A Conn may be accepted from a Listener, which listens on a specific local network ID.
//
// Dialer and Listener initially negotiates its offer/answer and local ICE candidates of Conn
// with a remote connection with an implementation of [Signaling].
//
// Once established using either Dialer or Listener, it will handle for messages sent in
// 'ReliableDataChannel' (which can be read from [Conn.Read] or [Conn.ReadPacket]), and
// closure of its ORTC transports that ensures all transports has been closed.
type Conn struct {
	ice  *webrtc.ICETransport
	dtls *webrtc.DTLSTransport
	sctp *webrtc.SCTPTransport

	// candidateReceived notifies that a first candidate is received from the other
	// end, and the Conn is ready to start its transports.
	candidateReceived chan struct{}
	// candidates includes all [webrtc.ICECandidate] signaled from the remote connection.
	// When a new [webrtc.ICECandidate] is signaled, it will be appended atomically into the slice.
	candidates   []webrtc.ICECandidate
	candidatesMu sync.Mutex // Guards above

	// negotiator is either Listener or Dialer.
	negotiator negotiator

	reliable, unreliable *webrtc.DataChannel // ReliableDataChannel and UnreliableDataChannel

	packets chan []byte

	// message includes a buffer of all previously-received segments, and last segment count.
	message *message

	once   sync.Once     // Closes below only once.
	closed chan struct{} // Notifies that a Conn has been closed.

	log *slog.Logger

	local         Addr
	id, networkID uint64
}

// Read reads a message received in [webrtc.DataChannel] labeled 'ReliableDataChannel'.
// The bytes of message data will be copied into the buffer. An error may be returned if the [Conn]
// has closed by [Conn.Close].
func (c *Conn) Read(b []byte) (n int, err error) {
	select {
	case <-c.closed:
		return n, net.ErrClosed
	case pk := <-c.packets:
		return copy(b, pk), nil
	}
}

// ReadPacket reads a message received in [webrtc.DataChannel] labeled 'ReliableDataChannel',
// and returns the bytes. It is implemented for Minecraft read operations to avoid some bug
// related to use the Read method in decoder.
func (c *Conn) ReadPacket() ([]byte, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case pk := <-c.packets:
		return pk, nil
	}
}

// Write writes a message that contains the data into [webrtc.DataChannel] labeled 'ReliableDataChannel'
// with segments. If the data length exceeds 10000 bytes, it will be split in a multiple segments. An error
// may be returned while writing a segment into the [webrtc.DataChannel], or the [Conn] has closed by [Conn.Close].
func (c *Conn) Write(b []byte) (n int, err error) {
	select {
	case <-c.closed:
		return n, net.ErrClosed
	default:
		segments := uint8(len(b) / maxMessageSize)
		if len(b)%maxMessageSize != 0 {
			segments++ // If there's a remainder, we need an additional segment.
		}

		for i := 0; i < len(b); i += maxMessageSize {
			segments--

			end := i + maxMessageSize
			if end > len(b) {
				end = len(b)
			}
			frag := b[i:end]
			if err := c.reliable.Send(append([]byte{segments}, frag...)); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					return n, net.ErrClosed
				}
				return n, fmt.Errorf("write segment #%d: %w", segments, err)
			}
			n += len(frag)
		}
		return n, nil
	}
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

// LocalAddr returns an Addr with the local network ID of the Conn. It also contains
// locally-gathered ICE candidates.
func (c *Conn) LocalAddr() net.Addr {
	addr := c.local
	addr.ConnectionID = c.id
	return &addr
}

// RemoteAddr returns an Addr with the remote network ID of the Conn. It also contains
// remotely-signaled ICE candidates, which is atomically added when a Signal of SignalTypeCandidate
// is handled.
func (c *Conn) RemoteAddr() net.Addr {
	addr := c.remoteAddr()

	c.candidatesMu.Lock()
	addr.Candidates = slices.Clone(c.candidates)
	c.candidatesMu.Unlock()
	return addr
}

func (c *Conn) remoteAddr() *Addr {
	return &Addr{
		NetworkID:    c.networkID,
		ConnectionID: c.id,
	}
}

// Close closes two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel' first,
// then closes the SCTP, DTLS and ICE transport of the Conn once. An error joined using [errors.Join]
// may be returned, which contains non-nil errors occurred during stopping the things.
func (c *Conn) Close() (err error) {
	c.once.Do(func() {
		close(c.closed)

		c.negotiator.handleClose(c)

		errs := make([]error, 0, 5)
		errs = append(errs, c.reliable.Close())
		errs = append(errs, c.unreliable.Close())
		errs = append(errs, c.sctp.Stop())
		errs = append(errs, c.dtls.Stop())
		errs = append(errs, c.ice.Stop())
		err = errors.Join(errs...)
	})
	return err
}

// handleTransports handles remote messages received in reliable [webrtc.DataChannel],
// and closure of its two data channels, ICE, DTLS and SCTP transport to ensure that all
// transports has been closed when one of them has been closed by the remote connection.
func (c *Conn) handleTransports() {
	c.reliable.OnMessage(func(msg webrtc.DataChannelMessage) {
		if err := c.handleMessage(msg.Data); err != nil {
			c.log.Error("error handling remote message", internal.ErrAttr(err))
		}
	})

	c.reliable.OnClose(func() {
		_ = c.Close()
	})

	c.unreliable.OnClose(func() {
		_ = c.Close()
	})

	c.ice.OnConnectionStateChange(func(state webrtc.ICETransportState) {
		switch state {
		case webrtc.ICETransportStateClosed, webrtc.ICETransportStateDisconnected, webrtc.ICETransportStateFailed:
			// This negotiator function itself is holding the lock, call Close in a goroutine.
			go c.Close() // We need to make sure that all transports has been closed
		default:
		}
	})
	c.dtls.OnStateChange(func(state webrtc.DTLSTransportState) {
		switch state {
		case webrtc.DTLSTransportStateClosed, webrtc.DTLSTransportStateFailed:
			// This negotiator function itself is holding the lock, call Close in a goroutine.
			go c.Close() // We need to make sure that all transports has been closed
		default:
		}
	})
}

// handleSignal handles an incoming Signal signaled from the remote connection.
//
// If the Signal is of SignalTypeCandidate, it will parse a [webrtc.ICECandidate] from its data
// and adds to the ICE transport of the Conn.
//
// If the Signal is of SignalTypeError, it will close the Conn immediately as failed.
func (c *Conn) handleSignal(signal *Signal) error {
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

		if err := c.ice.AddRemoteCandidate(&i); err != nil {
			return fmt.Errorf("add remote candidate: %w", err)
		}

		c.candidatesMu.Lock()
		if len(c.candidates) == 0 {
			close(c.candidateReceived)
		}
		c.candidates = append(c.candidates, i)
		c.candidatesMu.Unlock()
	case SignalTypeError:
		code, err := strconv.ParseUint(signal.Data, 10, 32)
		if err != nil {
			return fmt.Errorf("parse error code: %w", err)
		}
		c.log.Error("connection failed with error", slog.Uint64("code", code))
		if err := c.Close(); err != nil {
			return fmt.Errorf("close: %w", err)
		}
	default:
		return fmt.Errorf("unknown signal type: %s", signal.Type)
	}
	return nil
}

const maxMessageSize = 10000

// parseDescription parses a [sdp.SessionDescription] signaled from the remote connection.
// It will validate its fields and transforms/returns into a description, which can be used
// for starting the ICE, DTLS and SCTP transports of a Conn.
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
	case "active":
		role = webrtc.DTLSRoleClient
	case "actpass":
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

// description contains parameters for opening ICE, DTLS and SCTP transport.
//
// A description may be parsed by a negotiator (Listener or Dialer) using parseDescription
// with a [sdp.SessionDescription] decoded from a Signal of SignalTypeOffer or SignalTypeAnswer.
//
// A description may be filled in by a negotiator (Listener or Dialer) to encode
// a local description of a Conn.
type description struct {
	ice  webrtc.ICEParameters
	dtls webrtc.DTLSParameters
	sctp webrtc.SCTPCapabilities
}

// encode transforms the description into [sdp.SessionDescription] and encodes
// them using the [sdp.SessionDescription.Marshal] method. It is called by a negotiator
// (Listener or Dialer) with its description filled in with the local parameters to
// signal a Signal of SignalTypeOffer or SignalTypeAnswer to the remote connection.
func (desc description) encode() ([]byte, error) {
	d := &sdp.SessionDescription{
		Version: 0x2,
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
			{Key: "group", Value: "BUNDLE 0"},
			{Key: "extmap-allow-mixed", Value: ""},
			{Key: "msid-semantic", Value: " WMS"},
		},
		MediaDescriptions: []*sdp.MediaDescription{
			{
				MediaName: sdp.MediaName{
					Media:   "application",
					Port:    sdp.RangedPort{Value: 9},
					Protos:  []string{"UDP", "DTLS", "SCTP"},
					Formats: []string{"webrtc-datachannel"},
				},
				ConnectionInformation: &sdp.ConnectionInformation{
					NetworkType: "IN",
					AddressType: "IP4",
					Address:     &sdp.Address{Address: "0.0.0.0"},
				},
				Attributes: []sdp.Attribute{
					{Key: "ice-ufrag", Value: desc.ice.UsernameFragment},
					{Key: "ice-pwd", Value: desc.ice.Password},
					{Key: "ice-options", Value: "trickle"},
					{Key: "fingerprint", Value: fmt.Sprintf("%s %s",
						desc.dtls.Fingerprints[0].Algorithm,
						desc.dtls.Fingerprints[0].Value,
					)},
					desc.setupAttribute(),
					{Key: "mid", Value: "0"},
					{Key: "sctp-port", Value: "5000"},
					{Key: "max-message-size", Value: strconv.FormatUint(uint64(desc.sctp.MaxMessageSize), 10)},
				},
			},
		},
	}
	return d.Marshal()
}

// setupAttribute returns a [sdp.Attribute] with the key 'setup' of value
// "active" or "actpass" based on the role of local DTLS parameters.
// It is called by encode to include them to the media description of local
// [sdp.SessionDescription].
func (desc description) setupAttribute() sdp.Attribute {
	attr := sdp.Attribute{Key: "setup"}
	if desc.dtls.Role == webrtc.DTLSRoleServer {
		attr.Value = "actpass"
	} else {
		attr.Value = "active"
	}
	return attr
}

// newConn creates a Conn from the ICE, DTLS and SCTP transport associated with the IDs. The local Addr containing the local network ID
// will be used for returning local [net.Addr] of the Conn from [Conn.LocalAddr]. The negotiator (caller) must establish each transport
// after creating a Conn when an ICE candidate has been signaled from the remote connection once. An implementation of negotiator may be
// used to obtain a [slog.Logger] of the Conn, and few other methods to handle events such as closures.
func newConn(ice *webrtc.ICETransport, dtls *webrtc.DTLSTransport, sctp *webrtc.SCTPTransport, id, networkID uint64, local Addr, n negotiator) *Conn {
	return &Conn{
		ice:  ice,
		dtls: dtls,
		sctp: sctp,

		candidateReceived: make(chan struct{}, 1),

		negotiator: n,

		packets: make(chan []byte),

		message: &message{},

		closed: make(chan struct{}, 1),

		log: n.log().With(slog.Group("connection",
			slog.Uint64("id", id),
			slog.Uint64("networkID", networkID),
		)),

		local: local,

		id:        id,
		networkID: networkID,
	}
}

type negotiator interface {
	// handleClose handles closure of the Conn. It is implemented for deleting closed connections on Listener.
	handleClose(conn *Conn)
	// log returns a base [slog.Logger] to be used as the logger of Conn. The Conn extends the [slog.Logger]
	// with few additional attributes such as ID and network ID of the Conn.
	log() *slog.Logger
}

var ErrUnsupported = errors.New("nethernet: unsupported")
