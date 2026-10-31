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
			if l.conf.BroadcastAddress != nil || !l.directedBroadcast {
				t.Fatalf("BroadcastAddress = %v, directed = %t; want directed broadcasts", l.conf.BroadcastAddress, l.directedBroadcast)
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
		notifiers: make(map[uint32]nethernet.Notifier),
	}

	first := newSignalRecorder()
	stopFirst := l.Notify(first)
	defer stopFirst()
	second := newSignalRecorder()
	stopSecond := l.Notify(second)
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

	signal.ConnectionID = 43
	if err := l.handleMessage(&MessagePacket{RecipientID: localID, Data: signal.String()}, senderID); err != nil {
		t.Fatalf("handleMessage after stop: %v", err)
	}
	assertNoSignalReceived(t, first)
	assertSignalReceived(t, second, signal, senderID)
}

type signalRecorder struct {
	signals chan *nethernet.Signal
}

func newSignalRecorder() *signalRecorder {
	return &signalRecorder{signals: make(chan *nethernet.Signal, 4)}
}

func (r *signalRecorder) NotifySignal(signal *nethernet.Signal) bool {
	delivered := *signal
	r.signals <- &delivered
	return true
}

func assertSignalReceived(t *testing.T, recorder *signalRecorder, want *nethernet.Signal, senderID uint64) {
	t.Helper()

	select {
	case got := <-recorder.signals:
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

func assertNoSignalReceived(t *testing.T, recorder *signalRecorder) {
	t.Helper()

	select {
	case signal := <-recorder.signals:
		t.Fatalf("unexpected signal after stop: %#v", signal)
	case <-time.After(time.Millisecond * 50):
	}
}

// Requests and a zero sender never locate a peer; responses and messages do, as in vanilla.
func TestHandlePacketRecordsOnlyResponseAndMessageSenders(t *testing.T) {
	const localID uint64 = 1
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}
	for _, tt := range []struct {
		name   string
		pk     Packet
		sender uint64
		want   bool
	}{
		{name: "request", pk: &RequestPacket{}, sender: 2},
		{name: "response", pk: &ResponsePacket{ApplicationData: []byte{1}}, sender: 2, want: true},
		{name: "message", pk: &MessagePacket{RecipientID: localID, Data: "Ping"}, sender: 2, want: true},
		{name: "zeroSender", pk: &MessagePacket{RecipientID: localID, Data: "Ping"}, sender: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l := &Listener{
				conf:      ListenConfig{NetworkID: localID},
				addresses: make(map[uint64]address),
				responses: make(map[uint64]response),
			}
			l.pongData.Store(&[]byte{})
			l.conn = discardConn{}
			if err := l.handlePacket(Marshal(tt.pk, tt.sender), from); err != nil {
				t.Fatalf("handlePacket: %v", err)
			}
			if _, got := l.addresses[tt.sender]; got != tt.want {
				t.Fatalf("address recorded = %t, want %t", got, tt.want)
			}
		})
	}
}

// A peer's address stays usable for under a minute of silence, then expires.
func TestSignalExpiresPeerAddressAfterAMinute(t *testing.T) {
	const peerID uint64 = 2
	l := &Listener{
		conf:      ListenConfig{NetworkID: 1},
		addresses: make(map[uint64]address),
		closed:    make(chan struct{}),
		conn:      discardConn{},
	}
	signal := &nethernet.Signal{Type: nethernet.SignalTypeOffer, ConnectionID: 1, Data: "offer", NetworkID: strconv.FormatUint(peerID, 10)}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7551}

	l.addresses[peerID] = address{networkID: peerID, addr: from, t: time.Now().Add(-addressLifetime + time.Second)}
	if err := l.Signal(t.Context(), signal); err != nil {
		t.Fatalf("Signal to a peer seen 59s ago: %v", err)
	}
	l.addresses[peerID] = address{networkID: peerID, addr: from, t: time.Now().Add(-addressLifetime)}
	if err := l.Signal(t.Context(), signal); err == nil {
		t.Fatal("Signal reached a peer silent for a minute")
	}
}

// discardConn accepts writes without sending them.
type discardConn struct{ net.PacketConn }

func (discardConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }

// A LAN world stays listed while its latest response is at most five seconds old, as in vanilla.
func TestResponsesExpireAfterFiveSeconds(t *testing.T) {
	now := time.Now()
	l := &Listener{responses: map[uint64]response{
		1: {data: []byte("fresh"), t: now.Add(-responseLifetime)},
		2: {data: []byte("stale"), t: now.Add(-responseLifetime - time.Nanosecond)},
	}}
	got := l.responsesAt(now)
	if string(got[1]) != "fresh" {
		t.Fatalf("responses[1] = %q, want %q", got[1], "fresh")
	}
	if _, ok := got[2]; ok {
		t.Fatal("kept a server silent for over five seconds")
	}
}

// A peer's address is kept while under a minute old and forgotten at exactly a minute, as in vanilla.
func TestDeleteInactiveAddressesAtOneMinute(t *testing.T) {
	now := time.Now()
	l := &Listener{addresses: map[uint64]address{
		1: {networkID: 1, t: now.Add(-addressLifetime + time.Nanosecond)},
		2: {networkID: 2, t: now.Add(-addressLifetime)},
	}}
	l.deleteInactiveAddressesLocked(now)
	if _, ok := l.addresses[1]; !ok {
		t.Fatal("forgot a peer heard from under a minute ago")
	}
	if _, ok := l.addresses[2]; ok {
		t.Fatal("kept a peer silent for a minute")
	}
}

// A network's directed broadcast address sets every host bit, as vanilla computes it.
func TestDirectedBroadcast(t *testing.T) {
	for _, tt := range []struct {
		cidr, want string
	}{
		{"192.168.1.20/24", "192.168.1.255"},
		{"10.0.3.7/22", "10.0.3.255"},
		{"172.16.5.4/16", "172.16.255.255"},
	} {
		ip, network, err := net.ParseCIDR(tt.cidr)
		if err != nil {
			t.Fatal(err)
		}
		network.IP = ip
		got, ok := directedBroadcast(network)
		if !ok || net.IP(got[:]).String() != tt.want {
			t.Fatalf("directedBroadcast(%s) = %v, %t, want %s", tt.cidr, net.IP(got[:]), ok, tt.want)
		}
	}
	if _, ok := directedBroadcast(&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}); ok {
		t.Fatal("directedBroadcast accepted an IPv6 network")
	}
}
