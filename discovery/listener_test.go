package discovery

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestListenAcceptsClientAddressForms(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr string
	}{
		{name: "empty", addr: ""},
		{name: "portZero", addr: ":0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, err := (ListenConfig{}).Listen(tt.addr)
			if err != nil {
				t.Fatalf("Listen(%q): %v", tt.addr, err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})

			localAddr, ok := l.conn.LocalAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("local address = %T, want *net.UDPAddr", l.conn.LocalAddr())
			}
			if localAddr.Port == DefaultPort {
				t.Skipf("port-zero bind selected default port %d", DefaultPort)
			}
			if l.conf.BroadcastAddress == nil {
				t.Fatal("BroadcastAddress is nil")
			}
			if !l.conf.BroadcastAddress.IP.Equal(net.IPv4bcast) {
				t.Fatalf("BroadcastAddress.IP = %v, want %v", l.conf.BroadcastAddress.IP, net.IPv4bcast)
			}
			if l.conf.BroadcastAddress.Port != DefaultPort {
				t.Fatalf("BroadcastAddress.Port = %d, want %d", l.conf.BroadcastAddress.Port, DefaultPort)
			}
		})
	}
}

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

func TestNotifyBroadcastsToMultipleSubscribers(t *testing.T) {
	const (
		localID  uint64 = 1
		senderID uint64 = 2
	)
	l := &Listener{
		conf:      ListenConfig{NetworkID: localID},
		notifiers: make(map[uint32]chan *nethernet.Signal),
	}

	first, stopFirst := l.Notify()
	defer stopFirst()
	second, stopSecond := l.Notify()
	defer stopSecond()

	signal := &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 42,
		Data:         "offer",
	}
	if err := l.handleMessage(&MessagePacket{RecipientID: localID, Data: signal.String()}, senderID); err != nil {
		t.Fatalf("handleMessage: %v", err)
	}
	assertSignalReceived(t, first, signal, senderID)
	assertSignalReceived(t, second, signal, senderID)

	stopFirst()
	if _, ok := <-first; ok {
		t.Fatal("first subscription still open after stop")
	}

	signal.ConnectionID = 43
	if err := l.handleMessage(&MessagePacket{RecipientID: localID, Data: signal.String()}, senderID); err != nil {
		t.Fatalf("handleMessage after stop: %v", err)
	}
	assertSignalReceived(t, second, signal, senderID)
}

func assertSignalReceived(t *testing.T, signals <-chan *nethernet.Signal, want *nethernet.Signal, senderID uint64) {
	t.Helper()

	select {
	case got, ok := <-signals:
		if !ok {
			t.Fatal("signal channel closed")
		}
		if got.Type != want.Type {
			t.Fatalf("signal type = %q, want %q", got.Type, want.Type)
		}
		if got.ConnectionID != want.ConnectionID {
			t.Fatalf("connection ID = %d, want %d", got.ConnectionID, want.ConnectionID)
		}
		if got.Data != want.Data {
			t.Fatalf("data = %q, want %q", got.Data, want.Data)
		}
		wantNetworkID := strconv.FormatUint(senderID, 10)
		if got.NetworkID != wantNetworkID {
			t.Fatalf("network ID = %q, want %q", got.NetworkID, wantNetworkID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal")
	}
}
