package discovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
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
	marshal(buf, pk, senderID)

	b := encrypt(buf.Bytes())

	hash := hmac.New(sha256.New, key[:])
	hash.Write(buf.Bytes())
	b = append(hash.Sum(nil), b...)
	return b
}

// marshal writes the given packet with the header containing the given sender ID.
func marshal(w io.Writer, pk Packet, senderID uint64) {
	buf := &bytes.Buffer{}
	h := &Header{
		PacketID: pk.ID(),
		SenderID: senderID,
		// The vanilla client seems to set this to true for every packet
		// including non-reliable ones.
		Reliable: true,
	}
	h.Write(buf)
	pk.Write(buf)

	// Vanilla counts the whole decrypted payload, including this prefix.
	length := buf.Len() + 2
	if m, ok := pk.(*MessagePacket); ok {
		length = messageHeaderLength + declaredMessageLength(m.Data)
	}
	_ = binary.Write(w, binary.LittleEndian, uint16(length))
	_, _ = buf.WriteTo(w)
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
	if checksum := hash.Sum(nil); !bytes.Equal(b[:32], checksum) {
		return nil, 0, fmt.Errorf("checksum mismatch: %x != %x", b[:32], checksum)
	}
	if len(payload) < 4 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return unmarshal(bytes.NewBuffer(payload))
}

// unmarshal decodes the packet and sender ID from the raw bytes passed.
// A list of expected packet IDs may be listed as the variadic parameters.
func unmarshal(r io.Reader, expectedIDs ...uint16) (Packet, uint64, error) {
	var length uint16
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, 0, fmt.Errorf("read length: %w", err)
	}
	if l, ok := r.(interface {
		Len() int
	}); ok && l.Len()+2 < int(length) {
		return nil, 0, fmt.Errorf("payload length %d is less than declared %d", l.Len(), length)
	}
	h := &Header{}
	if err := h.Read(r); err != nil {
		return nil, 0, fmt.Errorf("read header: %w", err)
	}
	if len(expectedIDs) > 0 && !slices.Contains(expectedIDs, h.PacketID) {
		return nil, 0, fmt.Errorf("unexpected packet ID: %d", h.PacketID)
	}
	var reliable bool
	var pk Packet
	switch h.PacketID {
	case IDRequestPacket:
		pk = &RequestPacket{}
	case IDResponsePacket:
		pk = &ResponsePacket{}
	case IDMessagePacket:
		pk = &MessagePacket{}
	case IDReliablePacket:
		pk, reliable = &ReliablePacket{}, true
	case IDAcknowledgementPacket:
		pk, reliable = &AcknowledgementPacket{}, true
	default:
		return nil, h.SenderID, fmt.Errorf("unknown packet ID: %d", h.PacketID)
	}
	if !h.Reliable && reliable {
		return nil, h.SenderID, fmt.Errorf("reliable packet without reliable flag: %T", pk)
	}
	if err := pk.Read(r); err != nil {
		return nil, h.SenderID, err
	}
	return pk, h.SenderID, nil
}

// readBytes skips a uint32 length prefix and returns every byte after it,
// since vanilla ignores that prefix and reads to the end of the payload.
func readBytes(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	if n := len(data); int(length) > n {
		return nil, fmt.Errorf("payload is shorter than declared length: %d", n)
	}
	return data, nil
}

// writeBytes writes bytes into the [io.Writer] prefixed with a length for the generic type (uint32 or uint8).
func writeBytes[L ~uint32 | ~uint8](w io.Writer, b []byte) {
	_ = binary.Write(w, binary.LittleEndian, (L)(len(b)))
	_, _ = w.Write(b)
}

const (
	IDRequestPacket uint16 = iota
	IDResponsePacket
	IDMessagePacket
	IDReliablePacket
	IDAcknowledgementPacket
)

// Header describes the binary structure of the initial bytes of a packet
// transmitted during LAN discovery.
type Header struct {
	// PacketID is the ID of the packet.
	PacketID uint16
	// SenderID is the ID of the network that sent the packet.
	SenderID uint64
	// Reliable indicates whether this packet is reliable.
	// Reliable and Acknowledgement packets need this field to be set to
	// true, otherwise clients will reject them.
	Reliable bool
}

// Read reads and decodes the Header from the [io.Reader].
func (h *Header) Read(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &h.PacketID); err != nil {
		return fmt.Errorf("read packet ID: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &h.SenderID); err != nil {
		return fmt.Errorf("read sender ID: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &h.Reliable); err != nil {
		return fmt.Errorf("read reliable: %w", err)
	}
	b := make([]byte, 7)
	if _, err := r.Read(b); err != nil {
		return err
	}
	return nil
}

// Write writes the binary structure of Header into the [io.Writer].
func (h *Header) Write(w io.Writer) {
	_ = binary.Write(w, binary.LittleEndian, h.PacketID)
	_ = binary.Write(w, binary.LittleEndian, h.SenderID)
	_ = binary.Write(w, binary.LittleEndian, h.Reliable)
	_, _ = w.Write(make([]byte, 7))
}
