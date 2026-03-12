package nethernet

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"sync"

	"github.com/pion/webrtc/v4"
)

// MessageReliability represents the reliability of messages sent in a data channel.
// It is an internal type specific to this package's implementation, and shouldn't
// be sent over network in any way.
type MessageReliability uint8

const (
	// MessageReliabilityReliable guarantees the ordering of messages. Currently, this is the
	// only reliability parameter used in the game.
	MessageReliabilityReliable MessageReliability = iota
	// MessageReliabilityUnreliable seems to be unused, and it is unclear how it
	// works with multiple segments as packet drops could leave the message data
	// in unconstructed state.
	// While it is technically possible to send or receive packets in this channel,
	// it is currently recommended to use only MessageReliabilityReliable.
	MessageReliabilityUnreliable

	messageReliabilityCapacity // Max value for MessageReliability, used as the capacity for array.
)

// Parameters returns a [webrtc.DataChannelParameters], which may be used for creating a data channel for
// the MessageReliability or to ensure that a data channel is valid to handle it in the Conn.
func (r MessageReliability) Parameters() *webrtc.DataChannelParameters {
	switch r {
	case MessageReliabilityReliable:
		return &webrtc.DataChannelParameters{
			Label:   "ReliableDataChannel",
			Ordered: true,
		}
	case MessageReliabilityUnreliable:
		param := uint16(0)
		return &webrtc.DataChannelParameters{
			Label:          "UnreliableDataChannel",
			MaxRetransmits: &param,
		}
	default:
		panic(fmt.Sprintf("nethernet: MessageReliability.Parameters: unknown value: %d", r))
	}
}

// Valid determines whether the [webrtc.DataChannel] can be safe to use in Conn.
// If the data channel does not have the exact same parameters returned by [MessageReliability.Parameters],
// it will return false.
func (r MessageReliability) Valid(channel *webrtc.DataChannel) bool {
	params := r.Parameters()
	// Compare non-pointer values
	if channel.Label() != params.Label ||
		channel.Protocol() != params.Protocol ||
		channel.Ordered() != params.Ordered ||
		channel.Negotiated() != params.Negotiated {
		return false
	}
	// Compare pointer values that should be compared deeply with the underlying values
	return r.compareOptional(channel.MaxPacketLifeTime(), params.MaxPacketLifeTime) &&
		r.compareOptional(channel.MaxRetransmits(), params.MaxRetransmits)
}

// compareOptional returns true if both optional uint16 values are equal.
// It evaluates two nil *uint16s as equal, and if both pointers are non nil,
// it compares the underlying uint16 values. If one is nil and the other is not,
// it returns false.
func (r MessageReliability) compareOptional(a, b *uint16) bool {
	if a != nil && b != nil {
		return *a == *b
	}
	return a == nil && b == nil
}

// wrapDataChannel wraps a [webrtc.DataChannel] into the dataChannel for further use in Conn.
// It also newly allocates a buffer in the message field of dataChannel sized for the maximum
// number of segments supported by the on-wire format.
func wrapDataChannel(channel *webrtc.DataChannel, reliability MessageReliability, conn *Conn) *dataChannel {
	ch := &dataChannel{
		DataChannel: channel,
		reliability: reliability,
		message: &message{
			// max remaining-segment count (first byte in the message) is MaxUint8, meaning the total number
			// of segments is MaxUint8+1.
			data: make([]byte, 0, (int(math.MaxUint8)+1)*maxMessageSize),
		},
		packets: make(chan []byte),
		close:   make(chan struct{}),
	}
	ch.OnMessage(func(msg webrtc.DataChannelMessage) {
		if err := ch.handleMessage(msg.Data); err != nil {
			if errors.Is(err, net.ErrClosed) {
				conn.log.Debug("message dropped due to closure of data channel",
					slog.String("label", ch.Label()))
				return
			}
			// Receiving an invalid or incomplete message is considered unrecoverable
			// as segmented packets cannot be completed. Closing the connection also
			// helps mitigate malformed or malicious input from a peer.
			// The DataChannel invokes this callback while holding an internal lock,
			// so the connection is closed in a goroutine to avoid deadlock.
			go conn.close(fmt.Errorf("nethernet: handle message in %s: %w", ch.Label(), err))
		}
	})
	ch.OnClose(func() {
		// This handler function itself is invoked while holding an internal lock, so call close in a goroutine to avoid deadlock.
		go conn.close(fmt.Errorf("nethernet: data channel %q closed by remote peer", ch.Label()))
	})
	return ch
}

// dataChannel represents the data channel responsible for sending and receiving messages in MessageReliability
// within a Conn. It contains the fields necessary for handling multiple segments received in the embedded [webrtc.DataChannel].
type dataChannel struct {
	*webrtc.DataChannel

	// An embedded message contains the buffer that holds the segments received
	// to now and the count of the last segment count.
	*message

	// reliability is the reliability parameter for dataChannel.
	// It controls how multiple segments received in the data channel is handled.
	reliability MessageReliability

	// When writing multiple segments to the dataChannel, it should be locked using
	// its embedded [sync.Mutex] for guaranteeing ordered segment counts.
	write sync.Mutex

	// packets can be used to receive packets that are fully-reconstructed from
	// one or more segments received in the dataChannel.
	packets chan []byte

	// close is a channel that is closed when a dataChannel is closed.
	close chan struct{}
	// once ensures the dataChannel is closed only once.
	once sync.Once
}

// message represents the structure of remote messages sent in ReliableDataChannel.
type message struct {
	// segments represents the number of segments the message is split into.
	segments uint8
	// data represents the payload of the message.
	data []byte
}

// parseMessage parses the provided data into a message. The first byte indicates the count of segments,
// and the remaining bytes are its payload. If the data is less than 2 bytes, an error is returned.
func parseMessage(b []byte) (*message, error) {
	if len(b) < 2 {
		return nil, io.ErrUnexpectedEOF
	}
	return &message{
		segments: b[0],
		data:     b[1:],
	}, nil
}

// handleMessage handles a message received from a [webrtc.DataChannel] for the reliability. It parses
// the incoming data into a message using parseMessage and handles the segments, and if all segments has
// been received, it sends the buffer to either [Conn.Read] or [Conn.ReadPacket].
func (c *dataChannel) handleMessage(b []byte) error {
	select {
	case <-c.close:
		return net.ErrClosed
	default:
	}

	msg, err := parseMessage(b)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	if c.reliability == MessageReliabilityUnreliable && msg.segments > 0 {
		return fmt.Errorf("unexpected segment count on UnreliableDataChannel: %d", msg.segments)
	}

	if c.segments > 0 && c.segments-1 != msg.segments {
		return fmt.Errorf("invalid promised segments: expected %d, got %d", c.segments-1, msg.segments)
	}

	c.segments = msg.segments
	c.data = append(c.data, msg.data...)

	if c.segments > 0 {
		return nil
	}

	select {
	case <-c.close:
		return net.ErrClosed
	case c.packets <- c.data:
		c.data = nil
	}

	return nil
}

// Close closes the underlying [webrtc.DataChannel].
func (c *dataChannel) Close() (err error) {
	c.once.Do(func() {
		close(c.close)
		clear(c.data)
		err = c.DataChannel.Close()
	})
	return err
}
