package discovery

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MessagePacket is sent by both server and client to negotiate a NetherNet connection.
type MessagePacket struct {
	// RecipientID is the ID of NetherNet network that has sent the packet. Note that
	// this is not connection ID, which is included in the Data and only used once in
	// negotiation while network ID may be used across many connections.
	RecipientID uint64
	// Data is the actual data for signaling. It contains the string form of nethernet.Signal.
	Data string
}

// ID ...
func (*MessagePacket) ID() uint16 { return IDMessagePacket }

// Read ...
func (pk *MessagePacket) Read(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &pk.RecipientID); err != nil {
		return fmt.Errorf("read recipient ID: %w", err)
	}
	data, err := readBytes[uint32](r)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	pk.Data = string(data)
	return nil
}

// Write ...
func (pk *MessagePacket) Write(w io.Writer) {
	_ = binary.Write(w, binary.LittleEndian, pk.RecipientID)
	writeBytes[uint32](w, []byte(pk.Data))
}
