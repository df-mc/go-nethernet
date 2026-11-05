package discovery

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"golang.org/x/net/ipv6"
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

// parseNetwork returns cidr as an address on an up multicast interface.
func parseNetwork(t *testing.T, cidr string, ifIndex int) localNetwork {
	t.Helper()
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatal(err)
	}
	network.IP = ip
	return localNetwork{network, ifIndex, true}
}

// The domain follows vanilla's address filters, sets every host bit, and holds each target once.
func TestBroadcastDomain(t *testing.T) {
	var networks []localNetwork
	for _, cidr := range []string{
		"127.0.0.1/8", "::1/128", "169.254.1.5/16", "0.1.2.3/8", "10.1.2.3/4", "192.168.1.5/0",
		"192.168.1.20/24", "192.168.1.21/24", "10.0.3.7/22", "172.16.5.4/16",
		"fe80::1/64", "2001:db8::1/64", "2001:db8::2/64",
	} {
		networks = append(networks, parseNetwork(t, cidr, 1))
	}
	networks = append(networks, parseNetwork(t, "fd77::1/64", 2))
	noMulticast := parseNetwork(t, "fd78::1/64", 3)
	noMulticast.multicast = false
	networks = append(networks, noMulticast)

	domain := func(dualStack bool) string {
		var addrs []string
		for _, addr := range broadcastDomain(networks, DefaultPort, dualStack) {
			addrs = append(addrs, addr.String())
		}
		return strings.Join(addrs, " ")
	}
	const ipv4 = "192.168.1.255:7551 10.0.3.255:7551 172.16.255.255:7551"
	if got, want := domain(true), ipv4+" [ff02::1%1]:7551 [ff02::1%2]:7551"; got != want {
		t.Fatalf("dual-stack domain = %s, want %s", got, want)
	}
	if got := domain(false); got != ipv4 {
		t.Fatalf("IPv4 domain = %s, want %s", got, ipv4)
	}
}

// Link-local IPv6 alone sends nothing to the group, and a malformed mask must not panic the send loop.
func TestBroadcastDomainSkipsUnusableNetworks(t *testing.T) {
	networks := []localNetwork{
		parseNetwork(t, "fe80::1/64", 1),
		{IPNet: &net.IPNet{IP: net.IPv4(192, 168, 1, 20)}, ifIndex: 1},
	}
	if domain := broadcastDomain(networks, DefaultPort, true); len(domain) != 0 {
		t.Fatalf("domain = %v, want none", domain)
	}
}

// failingPacketConn fails sends to one host with err and records every destination.
type failingPacketConn struct {
	net.PacketConn
	host   string
	err    error
	writes []string
}

func (c *failingPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	host, _, _ := net.SplitHostPort(addr.String())
	c.writes = append(c.writes, host)
	if host == c.host {
		return 0, &net.OpError{Op: "write", Err: os.NewSyscallError("sendto", c.err)}
	}
	return len(b), nil
}

// A send error drops a destination only if it is one of vanilla's, without rediscovering the rest.
func TestBroadcastDropsUnreachableDestinations(t *testing.T) {
	bad, good := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 255)}, &net.UDPAddr{IP: net.IPv4(192, 168, 1, 255)}
	for _, err := range unreachableErrors {
		l := &Listener{conf: ListenConfig{Log: slog.Default()}, domain: []*net.UDPAddr{bad, good}}
		l.conn = &failingPacketConn{host: "10.0.0.255", err: err}
		l.broadcast(nil)
		if len(l.domain) != 1 || l.domain[0] != good {
			t.Fatalf("after %v: domain = %v, want [%v]", err, l.domain, good)
		}
	}

	l := &Listener{conf: ListenConfig{Log: slog.Default()}, domain: []*net.UDPAddr{bad, good}}
	l.conn = &failingPacketConn{host: "10.0.0.255", err: errors.New("no buffer space")}
	l.broadcast(nil)
	if len(l.domain) != 2 {
		t.Fatalf("other error: domain = %v, want both destinations", l.domain)
	}
}

// A send error on the configured address changes nothing and later sends still happen.
func TestBroadcastConfiguredAddress(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 255), Port: DefaultPort}
	conn := &failingPacketConn{host: "10.0.0.255", err: unreachableErrors[0]}
	l := &Listener{conf: ListenConfig{Log: slog.Default(), BroadcastAddress: addr}, conn: conn}
	l.broadcast(nil)
	l.broadcast(nil)
	if len(conn.writes) != 2 || l.domain != nil {
		t.Fatalf("writes = %v, domain = %v; want two sends and no domain", conn.writes, l.domain)
	}
}

// An empty domain sends to the fallback on the tick that rebuilds it, and interfaces are read again only
// while it stays empty.
func TestBroadcastRebuildsOnlyEmptyDomain(t *testing.T) {
	var (
		reads    int
		networks []localNetwork
	)
	read := func() []localNetwork {
		reads++
		return networks
	}
	conn := &failingPacketConn{}
	l := &Listener{conf: ListenConfig{Log: slog.Default()}, conn: conn}

	l.broadcast(read)
	networks = []localNetwork{parseNetwork(t, "192.168.1.20/24", 1)}
	l.broadcast(read)
	l.broadcast(read)
	l.broadcast(read)
	want := []string{"255.255.255.255", "255.255.255.255", "192.168.1.255", "192.168.1.255"}
	if !slices.Equal(conn.writes, want) {
		t.Fatalf("sends = %v, want %v", conn.writes, want)
	}
	if reads != 2 {
		t.Fatalf("interfaces read %d times, want 2", reads)
	}
}

// A Listener hosting nothing stays quiet on requests from peers, which now reach it on port 7551.
func TestHandleRequestWithoutServerDataIgnored(t *testing.T) {
	conn := &failingPacketConn{}
	l := &Listener{conf: ListenConfig{Log: slog.Default()}, conn: conn}
	if err := l.handleRequest(&net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: DefaultPort}); err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if len(conn.writes) != 0 {
		t.Fatalf("answered with no server data: %v", conn.writes)
	}
}

// An empty address takes the next ephemeral port once 7551 is held, while an explicit one fails.
func TestListenFallsBackOnlyForEmptyAddress(t *testing.T) {
	first, err := (ListenConfig{DisableRequests: true}).Listen("")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	if first.conn.LocalAddr().(*net.UDPAddr).Port != DefaultPort {
		t.Skipf("port %d is held by another process", DefaultPort)
	}

	second, err := (ListenConfig{DisableRequests: true}).Listen("")
	if err != nil {
		t.Fatalf("Listen(\"\") with 7551 held: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if second.conn.LocalAddr().(*net.UDPAddr).Port == DefaultPort {
		t.Fatal("second Listener bound the held port")
	}

	if l, err := (ListenConfig{DisableRequests: true}).Listen(":" + strconv.Itoa(DefaultPort)); err == nil {
		_ = l.Close()
		t.Fatal("explicit address bound a held port")
	}
}

// Each IPv6 interface joins the group once, with this host's own sends not looped back.
func TestJoinMulticast6(t *testing.T) {
	conn := &recordMulticast6{loopback: true}
	joinMulticast6(conn, []localNetwork{
		parseNetwork(t, "2001:db8::1/64", 1), parseNetwork(t, "2001:db8::2/64", 1),
		parseNetwork(t, "fd77::1/64", 2), parseNetwork(t, "fe80::1/64", 3), parseNetwork(t, "10.0.0.1/24", 4),
	}, slog.Default())
	if conn.loopback {
		t.Fatal("multicast loopback left on")
	}
	if want := []int{1, 2, 3}; !slices.Equal(conn.joins, want) {
		t.Fatalf("joined interfaces %v, want %v", conn.joins, want)
	}
}

// A request sent to the group on an interface reaches a joined socket through the real network stack.
func TestMulticast6RequestReachesJoinedSocket(t *testing.T) {
	l, err := (ListenConfig{DisableRequests: true}).Listen(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	l.ServerData(&ServerData{ServerName: "test"})

	local := l.conn.LocalAddr().(*net.UDPAddr)
	// A tunnel does not loop multicast back.
	groups := slices.DeleteFunc(broadcastDomain(localNetworks(), local.Port, l.dualStack), func(addr *net.UDPAddr) bool {
		index, err := strconv.Atoi(addr.Zone)
		if err != nil || !addr.IP.Equal(multicast6Group) {
			return true
		}
		iface, err := net.InterfaceByIndex(index)
		return err != nil || iface.Flags&net.FlagPointToPoint != 0
	})
	if len(groups) == 0 {
		t.Skip("host has no routable IPv6 LAN interface")
	}
	client, err := (ListenConfig{DisableRequests: true}).Listen(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := ipv6.NewPacketConn(client.conn).SetMulticastLoopback(true); err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		_ = client.write(&RequestPacket{}, group)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(client.Responses()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no response to a request sent to the group")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// recordMulticast6 records the calls made on a discovery socket.
type recordMulticast6 struct {
	loopback bool
	joins    []int
}

func (c *recordMulticast6) SetMulticastLoopback(on bool) error {
	c.loopback = on
	return nil
}

func (c *recordMulticast6) JoinGroup(ifi *net.Interface, _ net.Addr) error {
	c.joins = append(c.joins, ifi.Index)
	return nil
}

// Expiry windows must stay vanilla's exact magnitudes; the boundary tests pin only the comparison.
func TestExpiryLifetimesMatchVanilla(t *testing.T) {
	if responseLifetime != 5*time.Second {
		t.Errorf("responseLifetime = %v, want %v", responseLifetime, 5*time.Second)
	}
	if addressLifetime != time.Minute {
		t.Errorf("addressLifetime = %v, want %v", addressLifetime, time.Minute)
	}
}
