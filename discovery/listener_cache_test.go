package discovery

import (
	"net"
	"testing"
)

func TestHandlePacketUpdatesAddressForKnownSender(t *testing.T) {
	const (
		localID  uint64 = 1
		senderID uint64 = 2
	)
	l := &Listener{
		conf:      ListenConfig{NetworkID: localID},
		addresses: make(map[uint64]address),
	}
	packet := Marshal(&MessagePacket{RecipientID: localID, Data: "Ping"}, senderID)
	firstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}
	secondAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19133}

	if err := l.handlePacket(packet, firstAddr); err != nil {
		t.Fatalf("handlePacket(firstAddr): %v", err)
	}
	if err := l.handlePacket(packet, secondAddr); err != nil {
		t.Fatalf("handlePacket(secondAddr): %v", err)
	}

	got := l.addresses[senderID]
	if got.addr != secondAddr {
		t.Fatalf("cached addr = %v, want %v", got.addr, secondAddr)
	}
}
