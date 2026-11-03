package discovery

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MessagePacket is sent by both server and client to negotiate a NetherNet connection.
type MessagePacket struct {
	// RecipientID is the network ID to be signaled by MessagePacket. Note that this is
	// not the connection ID. The connection ID is included in the Data field and used only
	// during a single negotiation, whereas the network ID may be used across multiple connections.
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
	data, err := readRemaining(r)
	if err != nil {
		return fmt.Errorf("read data: %w", err)
	}
	pk.Data = string(data)
	return nil
}

// Write ...
func (pk *MessagePacket) Write(w io.Writer) {
	_ = binary.Write(w, binary.LittleEndian, pk.RecipientID)
	_ = binary.Write(w, binary.LittleEndian, uint32(declaredMessageLength(pk.Data)))
	_, _ = io.WriteString(w, pk.Data)
}

const (
	// messageHeaderLength is the decrypted size of a message before its data.
	messageHeaderLength = 32
	// maxDeclaredMessageData caps the data length vanilla declares; the full data still follows.
	maxDeclaredMessageData = 1140
)

// declaredMessageLength returns the data length vanilla writes for a message.
func declaredMessageLength(data string) int {
	return min(len(data), maxDeclaredMessageData)
}
