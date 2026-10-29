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

// Vanilla ignores nested data lengths and reads to the end of the payload.
func TestUnmarshalIgnoresNestedLengths(t *testing.T) {
	const declared = uint32(0xffff)

	pk, _, err := Unmarshal(rawPacket(IDMessagePacket, func(body *bytes.Buffer) {
		_ = binary.Write(body, binary.LittleEndian, uint64(2))
		_ = binary.Write(body, binary.LittleEndian, declared)
		body.WriteString("Ping")
	}))
	if err != nil {
		t.Fatalf("Unmarshal(message) error = %v", err)
	}
	if msg, ok := pk.(*MessagePacket); !ok || msg.Data != "Ping" {
		t.Fatalf("Unmarshal(message) = %#v, want data %q", pk, "Ping")
	}

	pk, _, err = Unmarshal(rawPacket(IDResponsePacket, func(body *bytes.Buffer) {
		_ = binary.Write(body, binary.LittleEndian, uint32(2))
		body.WriteString("0a0b0c")
	}))
	if err != nil {
		t.Fatalf("Unmarshal(response) error = %v", err)
	}
	if res, ok := pk.(*ResponsePacket); !ok || !bytes.Equal(res.ApplicationData, []byte{0x0a, 0x0b, 0x0c}) {
		t.Fatalf("Unmarshal(response) = %#v, want data 0a0b0c", pk)
	}
}

// A payload shorter than its declared length is dropped, as vanilla does.
func TestUnmarshalRejectsTruncatedPayload(t *testing.T) {
	if _, _, err := Unmarshal(requestPacket(1, 21)); err == nil {
		t.Fatal("Unmarshal() accepted a payload shorter than its declared length")
	}
}

// Vanilla declares at most 1140 bytes of message data but sends all of it.
func TestMarshalCapsDeclaredMessageLength(t *testing.T) {
	data := strings.Repeat("a", maxDeclaredMessageData+100)
	payload, err := decrypt(Marshal(&MessagePacket{RecipientID: 2, Data: data}, 1)[32:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := binary.LittleEndian.Uint16(payload); got != messageHeaderLength+maxDeclaredMessageData {
		t.Fatalf("declared payload length = %d, want %d", got, messageHeaderLength+maxDeclaredMessageData)
	}
	if got := binary.LittleEndian.Uint32(payload[28:]); got != maxDeclaredMessageData {
		t.Fatalf("declared data length = %d, want %d", got, maxDeclaredMessageData)
	}
	if got := string(payload[messageHeaderLength:]); got != data {
		t.Fatalf("message data length = %d, want %d", len(got), len(data))
	}

	payload, err = decrypt(Marshal(&MessagePacket{RecipientID: 2, Data: "Ping"}, 1)[32:])
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := binary.LittleEndian.Uint16(payload); int(got) != len(payload) {
		t.Fatalf("declared payload length = %d, want %d", got, len(payload))
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

func TestUnmarshalMessageDataPastDeclaredLength(t *testing.T) {
	const declared = "CONNECTREQUEST 1 v=0\r\n"
	const rest = "a=candidate:1 1 udp 1 192.168.1.2 50000 typ host\r\n"

	pk, _, err := Unmarshal(rawPacket(IDMessagePacket, func(body *bytes.Buffer) {
		_ = binary.Write(body, binary.LittleEndian, uint64(2))
		writeBytes[uint32](body, []byte(declared))
		body.WriteString(rest)
	}))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	msg, ok := pk.(*MessagePacket)
	if !ok {
		t.Fatalf("Unmarshal() packet = %T, want *MessagePacket", pk)
	}
	if msg.Data != declared+rest {
		t.Fatalf("Unmarshal() data = %q, want %q", msg.Data, declared+rest)
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
