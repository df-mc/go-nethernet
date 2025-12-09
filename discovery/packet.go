package discovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// Packet describes a packet used in LAN discovery.
type Packet interface {
	// ID uniquely returns the ID of the packet. It is one of the first byte
	// in the Header and used to identify which packet to decode in [Unmarshal].
	ID() uint16

	// Read reads/decodes the packet data from the [io.Reader].
	Read(r io.Reader) error
	// Write writes the packet data into the [io.Writer].
	Write(w io.Writer)
}

// Marshal encodes the packet into the bytes with using the sender ID.
func Marshal(pk Packet, senderID uint64) []byte {
	buf := &bytes.Buffer{}

	h := &Header{
		PacketID: pk.ID(),
		SenderID: senderID,
	}
	h.Write(buf)

	pk.Write(buf)

	payload := append(
		binary.LittleEndian.AppendUint16(nil, uint16(buf.Len())),
		buf.Bytes()...,
	)
	b := encrypt(payload)

	hash := hmac.New(sha256.New, key[:])
	hash.Write(payload)
	b = append(hash.Sum(nil), b...)
	return b
}

// Unmarshal decodes the packet from the bytes and returns them with an ID of the sender
// which has sent the packet. An error may be returned during decoding the content.
func Unmarshal(b []byte) (Packet, uint64, error) {
	if len(b) < 32 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	payload, err := decrypt(b[32:])
	if err != nil {
		return nil, 0, fmt.Errorf("decrypt: %w", err)
	}

	hash := hmac.New(sha256.New, key[:])
	hash.Write(payload)
	if checksum := hash.Sum(nil); bytes.Compare(b[:32], checksum) != 0 {
		return nil, 0, fmt.Errorf("checksum mismatch: %x != %x", b[:32], checksum)
	}
	buf := bytes.NewBuffer(payload)

	var length uint16
	if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
		return nil, 0, fmt.Errorf("read length: %w", err)
	}
	h := &Header{}
	if err := h.Read(buf); err != nil {
		return nil, 0, fmt.Errorf("read header: %w", err)
	}

	var pk Packet
	switch h.PacketID {
	case IDRequestPacket:
		pk = &RequestPacket{}
	case IDResponsePacket:
		pk = &ResponsePacket{}
	case IDMessagePacket:
		pk = &MessagePacket{}
	default:
		return nil, h.SenderID, fmt.Errorf("unknown packet ID: %d", h.PacketID)
	}
	if err := pk.Read(buf); err != nil {
		return nil, h.SenderID, err
	}
	if buf.Len() != 0 {
		return nil, h.SenderID, fmt.Errorf("unread %d bytes", buf.Len())
	}
	return pk, h.SenderID, nil
}

// readBytes reads bytes from the [io.Reader] prefixed with a length for the generic type (uint32 or uint8).
func readBytes[L ~uint32 | ~uint8](r io.Reader) ([]byte, error) {
	var length L
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	b := make([]byte, length)
	if n, err := r.Read(b); err != nil {
		return nil, err
	} else if n != int(length) {
		return nil, fmt.Errorf("invalid length: %d, expected %d", n, length)
	}
	return b, nil
}

// writeBytes writes bytes into the [io.Writer] prefixed with a length for the generic type (uint32 or uint8).
func writeBytes[L ~uint32 | ~uint8](w io.Writer, b []byte) {
	_ = binary.Write(w, binary.LittleEndian, (L)(len(b)))
	_, _ = w.Write(b)
}

const (
	// IDRequestPacket is the packet ID for RequestPacket.
	IDRequestPacket uint16 = iota
	// IDResponsePacket is the packet ID for ResponsePacket.
	IDResponsePacket
	// IDMessagePacket is the packet ID for MessagePacket.
	IDMessagePacket
)

// Header describes the binary structure of the initial bytes of a packet
// transmitted during LAN discovery.
type Header struct {
	// PacketID is the ID of the packet.
	PacketID uint16
	// SenderID is the ID of the network that sent the packet.
	SenderID uint64
}

// Read reads and decodes the Header from the [io.Reader].
func (h *Header) Read(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &h.PacketID); err != nil {
		return fmt.Errorf("read packet ID: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &h.SenderID); err != nil {
		return fmt.Errorf("read sender ID: %w", err)
	}
	if n, err := r.Read(make([]byte, 8)); err != nil {
		return fmt.Errorf("discard padding: %w", err)
	} else if n != 8 {
		return fmt.Errorf("%d != 8", n)
	}

	return nil
}

// Write writes the binary structure of Header into the [io.Writer].
func (h *Header) Write(w io.Writer) {
	_ = binary.Write(w, binary.LittleEndian, h.PacketID)
	_ = binary.Write(w, binary.LittleEndian, h.SenderID)
	_, _ = w.Write(make([]byte, 8))
}
