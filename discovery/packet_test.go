package discovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

func TestUnmarshalRejectsInvalidPacketLength(t *testing.T) {
	body := &bytes.Buffer{}
	(&Header{PacketID: IDRequestPacket, SenderID: 1}).Write(body)

	_, _, err := Unmarshal(sealPayload(append(
		binary.LittleEndian.AppendUint16(nil, uint16(body.Len()+1)),
		body.Bytes()...,
	)))
	if err == nil || !strings.Contains(err.Error(), "invalid packet length") {
		t.Fatalf("Unmarshal() error = %v, want invalid packet length", err)
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

func rawPacket(packetID uint16, write func(*bytes.Buffer)) []byte {
	body := &bytes.Buffer{}
	(&Header{PacketID: packetID, SenderID: 1}).Write(body)
	write(body)
	return sealPayload(append(
		binary.LittleEndian.AppendUint16(nil, uint16(body.Len())),
		body.Bytes()...,
	))
}

func sealPayload(payload []byte) []byte {
	hash := hmac.New(sha256.New, key[:])
	hash.Write(payload)
	return append(hash.Sum(nil), encrypt(payload)...)
}
