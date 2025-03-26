package nethernet

import (
	"fmt"
	"io"
)

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

// handleMessage handles a message received from a [webrtc.DataChannel] labeled 'ReliableDataChannel'.
// It parses the incoming data into a message using parseMessage and handles the segments, and if all
// segments has been received, it sends the message data to either [Conn.Read] or [Conn.ReadPacket].
func (c *Conn) handleMessage(b []byte) error {
	msg, err := parseMessage(b)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	} else if c.message.segments > 0 && c.message.segments-1 != msg.segments {
		return fmt.Errorf("invalid promised segments: expected %d, got %d", c.message.segments-1, msg.segments)
	}
	c.message.segments = msg.segments
	c.message.data = append(c.message.data, msg.data...)
	if c.message.segments > 0 {
		return nil
	}

	c.packets <- c.message.data
	c.message.data = nil
	return nil
}
