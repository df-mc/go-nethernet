package discovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPacketIDsStayStable(t *testing.T) {
	tests := []struct {
		name string
		got  uint16
		want uint16
	}{
		{name: "request", got: IDRequestPacket, want: 0},
		{name: "response", got: IDResponsePacket, want: 1},
		{name: "message", got: IDMessagePacket, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("packet ID = %d, want %d", tt.got, tt.want)
			}
		})
	}
}

func TestUnmarshalRejectsOversizedNestedLengths(t *testing.T) {
	const oversizedLength = uint32(maxPacketPayloadLength)

	tests := []struct {
		name     string
		packetID uint16
		write    func(*bytes.Buffer)
	}{
		{
			name:     "message data",
			packetID: IDMessagePacket,
			write: func(body *bytes.Buffer) {
				_ = binary.Write(body, binary.LittleEndian, uint64(2))
				_ = binary.Write(body, binary.LittleEndian, oversizedLength)
			},
		},
		{
			name:     "response application data",
			packetID: IDResponsePacket,
			write: func(body *bytes.Buffer) {
				_ = binary.Write(body, binary.LittleEndian, oversizedLength)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Unmarshal(rawPacket(tt.packetID, tt.write))
			if err == nil || !strings.Contains(err.Error(), "invalid length") {
				t.Fatalf("Unmarshal() error = %v, want invalid length", err)
			}
		})
	}
}

func TestUnmarshalAcceptsVanillaInclusiveLength(t *testing.T) {
	const senderID = 0x1020304050607080

	pk, gotSenderID, err := Unmarshal(requestPacket(senderID, 20))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if _, ok := pk.(*RequestPacket); !ok {
		t.Fatalf("Unmarshal() packet = %T, want *RequestPacket", pk)
	}
	if gotSenderID != senderID {
		t.Fatalf("Unmarshal() sender ID = %#x, want %#x", gotSenderID, senderID)
	}
}

func TestUnmarshalAcceptsLegacyExclusiveLength(t *testing.T) {
	const senderID = 0x1020304050607080

	pk, gotSenderID, err := Unmarshal(requestPacket(senderID, 18))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if _, ok := pk.(*RequestPacket); !ok {
		t.Fatalf("Unmarshal() packet = %T, want *RequestPacket", pk)
	}
	if gotSenderID != senderID {
		t.Fatalf("Unmarshal() sender ID = %#x, want %#x", gotSenderID, senderID)
	}
}

func TestMarshalWritesInclusiveLengthAndRoundTrips(t *testing.T) {
	const senderID = 0x1020304050607080

	b := Marshal(&RequestPacket{}, senderID)
	payload, err := decrypt(b[32:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	length := binary.LittleEndian.Uint16(payload[:2])
	if int(length) != len(payload) {
		t.Fatalf("Marshal() length = %d, want %d", length, len(payload))
	}

	pk, gotSenderID, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if _, ok := pk.(*RequestPacket); !ok {
		t.Fatalf("Unmarshal() packet = %T, want *RequestPacket", pk)
	}
	if gotSenderID != senderID {
		t.Fatalf("Unmarshal() sender ID = %#x, want %#x", gotSenderID, senderID)
	}
}

func rawPacket(packetID uint16, write func(*bytes.Buffer)) []byte {
	body := &bytes.Buffer{}
	(&Header{PacketID: packetID, SenderID: 1}).Write(body)
	write(body)
	return sealPayload(append(
		binary.LittleEndian.AppendUint16(nil, uint16(body.Len())),
		body.Bytes()...,
	))
}

// requestPacket builds an empty discovery request with a chosen length field.
func requestPacket(senderID uint64, length uint16) []byte {
	payload := make([]byte, 20)
	binary.LittleEndian.PutUint16(payload, length)
	binary.LittleEndian.PutUint16(payload[2:], IDRequestPacket)
	binary.LittleEndian.PutUint64(payload[4:], senderID)
	return sealPayload(payload)
}

// sealPayload encrypts and authenticates a decrypted discovery payload.
func sealPayload(payload []byte) []byte {
	hash := hmac.New(sha256.New, key[:])
	hash.Write(payload)
	return append(hash.Sum(nil), encrypt(payload)...)
}
