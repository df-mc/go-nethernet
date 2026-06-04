package discovery

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMarshalUnmarshalRoundTripsDiscoveryPackets(t *testing.T) {
	const senderID uint64 = 42

	tests := []struct {
		name   string
		packet Packet
		assert func(testing.TB, Packet)
	}{
		{
			name:   "request",
			packet: &RequestPacket{},
			assert: func(t testing.TB, got Packet) {
				t.Helper()
				if _, ok := got.(*RequestPacket); !ok {
					t.Fatalf("packet = %T, want *RequestPacket", got)
				}
			},
		},
		{
			name:   "response",
			packet: &ResponsePacket{ApplicationData: []byte{0, 1, 2, 0xff}},
			assert: func(t testing.TB, got Packet) {
				t.Helper()
				response, ok := got.(*ResponsePacket)
				if !ok {
					t.Fatalf("packet = %T, want *ResponsePacket", got)
				}
				if want := []byte{0, 1, 2, 0xff}; !bytes.Equal(response.ApplicationData, want) {
					t.Fatalf("ApplicationData = %v, want %v", response.ApplicationData, want)
				}
			},
		},
		{
			name:   "message",
			packet: &MessagePacket{RecipientID: 99, Data: "CONNECTREQUEST 7 payload"},
			assert: func(t testing.TB, got Packet) {
				t.Helper()
				message, ok := got.(*MessagePacket)
				if !ok {
					t.Fatalf("packet = %T, want *MessagePacket", got)
				}
				if message.RecipientID != 99 {
					t.Fatalf("RecipientID = %d, want 99", message.RecipientID)
				}
				if message.Data != "CONNECTREQUEST 7 payload" {
					t.Fatalf("Data = %q, want %q", message.Data, "CONNECTREQUEST 7 payload")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotSenderID, err := Unmarshal(Marshal(tt.packet, senderID))
			if err != nil {
				t.Fatalf("Unmarshal(Marshal()) error = %v, want nil", err)
			}
			if gotSenderID != senderID {
				t.Fatalf("sender ID = %d, want %d", gotSenderID, senderID)
			}
			tt.assert(t, got)
		})
	}
}

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
