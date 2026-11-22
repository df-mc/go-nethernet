package discovery

import (
	"encoding/binary"
	"fmt"
	"io"
)

type AcknowledgementPacket struct {
	RecipientID uint64
	Nonce       uint64
	Sequence    uint64
}

// ID ...
func (*AcknowledgementPacket) ID() uint16 {
	return IDAcknowledgementPacket
}

// Read ...
func (pk *AcknowledgementPacket) Read(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &pk.RecipientID); err != nil {
		return fmt.Errorf("read recipient ID: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &pk.Nonce); err != nil {
		return fmt.Errorf("read nonce: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &pk.Sequence); err != nil {
		return fmt.Errorf("read sequence: %w", err)
	}
	return nil
}

// Write ...
func (pk *AcknowledgementPacket) Write(w io.Writer) {
	_ = binary.Write(w, binary.LittleEndian, pk.RecipientID)
	_ = binary.Write(w, binary.LittleEndian, pk.Nonce)
	_ = binary.Write(w, binary.LittleEndian, pk.Sequence)
}
