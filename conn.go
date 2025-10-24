package nethernet

import (
	"errors"
	"fmt"
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

// Conn is an implementation of [net.Conn] for a peer connection between a specific remote
// NetherNet network/connection. Conn is safe for concurrent use by multiple goroutines except
// Read and ReadPacket.
//
// A Conn represents a WebRTC peer connection using ICE, DTLS, and SCTP transports and encapsulates
// two data channels labeled 'ReliableDataChannel' and 'UnreliableDataChannel'. Most methods within
// Conn utilize the 'ReliableDataChannel', as the functionality of the 'ReliableDataChannel' is less defined.
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
	candidatesMu sync.Mutex // Guards above

	// negotiator is either Listener or Dialer that the Conn has been negotiated through.
	negotiator negotiator

	reliable, unreliable *webrtc.DataChannel // ReliableDataChannel and UnreliableDataChannel

	packets chan []byte

	// message includes a buffer of previously-received segments and the count of the last segment.
	message *message

	once   sync.Once     // Ensures closure occur only once
	closed chan struct{} // Notifies that a Conn has been closed.

	log *slog.Logger

	local     Addr
	id        uint64
	networkID string
}

// Read receives a message from the 'ReliableDataChannel'. The bytes of the message data are copied to
// the given data. An error may be returned if the Conn has been closed by [Conn.Close].
func (c *Conn) Read(b []byte) (n int, err error) {
	select {
	case <-c.closed:
		return n, net.ErrClosed
	case pk := <-c.packets:
		return copy(b, pk), nil
	}
}

// ReadPacket receives a message from the 'ReliableDataChannel' and returns the bytes. It is
// implemented for Minecraft read operations to avoid some bugs related to the Read method in
// their decoder.
func (c *Conn) ReadPacket() ([]byte, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	case pk := <-c.packets:
		return pk, nil
	}
}

// PacketHeader always returns 0 and false as no header is prefixed before packets.
func (c *Conn) PacketHeader() (byte, bool) {
	return 0, false
}

// Write writes the data into the 'ReliableDataChannel'. If the data exceeds 10000 bytes, it is split into
// multiple segments. An error may be returned while writing a segment or if the Conn has been closed by [Conn.Close].
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
					err = net.ErrClosed
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

// LocalAddr returns an Addr that includes the local network ID of the Conn with locally-gathered
// ICE candidates.
func (c *Conn) LocalAddr() net.Addr {
	addr := c.local
	addr.ConnectionID = c.id
	pair, _ := c.ice.GetSelectedCandidatePair()
	if pair != nil {
		addr.SelectedCandidate = pair.Local
	}
	return &addr
}

// RemoteAddr returns an Addr that includes the remote network ID of the Conn with remotely-signaled
// ICE candidates. Candidates are atomically added when a Signal of type SignalTypeCandidate has been handled.
func (c *Conn) RemoteAddr() net.Addr {
	addr := c.remoteAddr()

	c.candidatesMu.Lock()
	addr.Candidates = slices.Clone(c.candidates)
	c.candidatesMu.Unlock()

	pair, _ := c.ice.GetSelectedCandidatePair()
	if pair != nil {
		addr.SelectedCandidate = pair.Remote
	}
	return addr
}

// remoteAddr returns a base Addr without ICE candidates signaled from the remote connection.
// It is used by [Conn.RemoteAddr] for returning the Addr with candidates and also by [Listener]
// for using Addr as the key for Conn.
func (c *Conn) remoteAddr() *Addr {
	return &Addr{
		NetworkID:    c.networkID,
		ConnectionID: c.id,
	}
}

// Close closes the 'ReliableDataChannel' and 'UnreliableDataChannel', then closes the SCTP, DTLS,
// and ICE transports of the Conn. An error may be returned using [errors.Join], which contains
// non-nil errors encountered during closure.
func (c *Conn) Close() (err error) {
	c.once.Do(func() {
		close(c.closed)

		c.negotiator.handleClose(c)

		if c.reliable != nil {
			err = c.reliable.Close()
		}
		if c.unreliable != nil {
			err = errors.Join(err, c.unreliable.Close())
		}

		err = errors.Join(
			err,
			c.sctp.Stop(),
			c.dtls.Stop(),
			c.ice.Stop(),
		)
	})
	return err
}

// handleTransports handles incoming messages from the 'ReliableDataChannel' and ensures
// closure of its two data channels, as well as ICE, DTLS, and SCTP transports when any of
// them are closed by the remote connection.
func (c *Conn) handleTransports() {
	c.reliable.OnMessage(func(msg webrtc.DataChannelMessage) {
		if err := c.handleMessage(msg.Data); err != nil {
			c.log.Error("error handling remote message", slog.Any("error", err))
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
			// This handler function itself is holding the lock, call Close in a goroutine.
			go c.Close() // We need to make sure that all transports has been closed
		default:
		}
	})
	c.dtls.OnStateChange(func(state webrtc.DTLSTransportState) {
		switch state {
		case webrtc.DTLSTransportStateClosed, webrtc.DTLSTransportStateFailed:
			// This handler function itself is holding the lock, call Close in a goroutine.
			go c.Close() // We need to make sure that all transports has been closed
		default:
		}
	})
	c.sctp.OnClose(func(err error) {
		// This handler function itself is holding the lock, call Close in a goroutine.
		go c.Close() // We need to make sure that all transports has been closed
	})
}

// handleSignal handles an incoming Signal signaled from the remote connection.
//
// If the Signal is of SignalTypeCandidate, it parses a [webrtc.ICECandidate] from its data and
// adds it to the ICE transport of the Conn.
//
// If the Signal is of SignalTypeError, it closes the Conn immediately.
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

		candidateReceived: make(chan struct{}, 1),

		negotiator: n,

		packets: make(chan []byte),

		message: &message{},

		closed: make(chan struct{}, 1),

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
