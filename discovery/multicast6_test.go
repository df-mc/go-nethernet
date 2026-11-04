package discovery

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"

	"golang.org/x/net/ipv6"
)

// discardLog keeps test output quiet while still exercising the logging branches.
var discardLog = slog.New(slog.NewTextHandler(io.Discard, nil))

var _ multicast6Conn = (*fakeMulticast6)(nil)

// fakeMulticast6 records the joins, loopback setting and sends made against it, and can fail a
// chosen interface.
type fakeMulticast6 struct {
	joined   []string
	iface    []string
	writes   []net.Addr
	loopback *bool
	failJoin map[string]error
	failIf   map[string]error
	failWS   map[string]error
	current  string // interface name set by the last SetMulticastInterface
}

func (c *fakeMulticast6) JoinGroup(ifi *net.Interface, group net.Addr) error {
	if err := c.failJoin[ifi.Name]; err != nil {
		return err
	}
	if ip, ok := group.(*net.IPAddr); !ok || !ip.IP.Equal(multicast6Group) {
		return &net.AddrError{Err: "join of unexpected group", Addr: group.String()}
	}
	c.joined = append(c.joined, ifi.Name)
	return nil
}

func (c *fakeMulticast6) SetMulticastInterface(ifi *net.Interface) error {
	if err := c.failIf[ifi.Name]; err != nil {
		return err
	}
	c.current = ifi.Name
	c.iface = append(c.iface, ifi.Name)
	return nil
}

func (c *fakeMulticast6) SetMulticastLoopback(on bool) error {
	c.loopback = &on
	return nil
}

func (c *fakeMulticast6) WriteTo(b []byte, _ *ipv6.ControlMessage, dst net.Addr) (int, error) {
	if err := c.failWS[c.current]; err != nil {
		return 0, err
	}
	c.writes = append(c.writes, dst)
	return len(b), nil
}

func ifaces(names ...string) []net.Interface {
	out := make([]net.Interface, len(names))
	for i, name := range names {
		out[i] = net.Interface{Index: i + 1, Name: name}
	}
	return out
}

// setupMulticast6 turns loopback off and joins ff02::1 on every interface.
func TestSetupMulticast6DisablesLoopbackAndJoins(t *testing.T) {
	c := &fakeMulticast6{}
	setupMulticast6(c, ifaces("eth0", "eth1"), discardLog)
	if c.loopback == nil || *c.loopback {
		t.Fatalf("multicast loopback = %v, want set to false", c.loopback)
	}
	if len(c.joined) != 2 || c.joined[0] != "eth0" || c.joined[1] != "eth1" {
		t.Fatalf("joined interfaces = %v, want [eth0 eth1]", c.joined)
	}
}

// joinMulticast6 joins ff02::1 on every interface and keeps going past one that fails.
func TestJoinMulticast6SkipsFailingInterface(t *testing.T) {
	c := &fakeMulticast6{failJoin: map[string]error{"eth1": net.ErrClosed}}
	if got := joinMulticast6(c, ifaces("eth0", "eth1", "eth2"), discardLog); got != 2 {
		t.Fatalf("joined = %d, want 2", got)
	}
	if len(c.joined) != 2 || c.joined[0] != "eth0" || c.joined[1] != "eth2" {
		t.Fatalf("joined interfaces = %v, want [eth0 eth2]", c.joined)
	}
}

// sendMulticast6Requests targets [ff02::1]:7551 on each interface.
func TestSendMulticast6RequestsTargetsGroupPerInterface(t *testing.T) {
	c := &fakeMulticast6{}
	sendMulticast6Requests(c, []byte("req"), ifaces("eth0", "eth1"), discardLog)
	if len(c.writes) != 2 {
		t.Fatalf("writes = %d, want 2", len(c.writes))
	}
	for _, dst := range c.writes {
		udp, ok := dst.(*net.UDPAddr)
		if !ok || !udp.IP.Equal(multicast6Group) || udp.Port != DefaultPort {
			t.Fatalf("write dst = %v, want [ff02::1]:%d", dst, DefaultPort)
		}
	}
}

// A host with no usable IPv6 interfaces sends nothing and does not error.
func TestSendMulticast6RequestsNoInterfacesIsNoOp(t *testing.T) {
	c := &fakeMulticast6{}
	sendMulticast6Requests(c, []byte("req"), nil, discardLog)
	if len(c.writes) != 0 || len(c.iface) != 0 {
		t.Fatalf("no-op expected, got %d writes over %v", len(c.writes), c.iface)
	}
}

// A failure selecting or writing on one interface does not stop the rest of the cycle.
func TestSendMulticast6RequestsContinuesPastFailures(t *testing.T) {
	c := &fakeMulticast6{
		failIf: map[string]error{"eth1": net.ErrClosed}, // selection fails: no write for eth1
		failWS: map[string]error{"eth2": io.ErrClosedPipe},
	}
	sendMulticast6Requests(c, []byte("req"), ifaces("eth0", "eth1", "eth2", "eth3"), discardLog)
	// eth0 and eth3 write; eth1 never selected; eth2 selected but its write fails.
	if len(c.writes) != 2 {
		t.Fatalf("successful writes = %d, want 2 (eth0, eth3)", len(c.writes))
	}
	if len(c.iface) != 3 {
		t.Fatalf("interfaces selected = %v, want eth0 eth2 eth3", c.iface)
	}
}

// supportsMulticast6 accepts only up, multicast-capable, non-loopback interfaces holding an IPv6 address.
func TestSupportsMulticast6(t *testing.T) {
	v6 := []net.Addr{&net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}}
	v4 := []net.Addr{&net.IPNet{IP: net.IPv4(192, 168, 1, 2), Mask: net.CIDRMask(24, 32)}}
	up := net.FlagUp | net.FlagMulticast
	for _, tt := range []struct {
		name  string
		flags net.Flags
		addrs []net.Addr
		want  bool
	}{
		{name: "upMulticastV6", flags: up, addrs: v6, want: true},
		{name: "down", flags: net.FlagMulticast, addrs: v6},
		{name: "noMulticast", flags: net.FlagUp, addrs: v6},
		{name: "loopback", flags: up | net.FlagLoopback, addrs: v6},
		{name: "onlyV4", flags: up, addrs: v4},
		{name: "noAddrs", flags: up},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := supportsMulticast6(tt.flags, tt.addrs); got != tt.want {
				t.Fatalf("supportsMulticast6 = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestMulticast6GroupIsAllNodes(t *testing.T) {
	if !multicast6Group.Equal(net.ParseIP("ff02::1")) {
		t.Fatalf("multicast6Group = %v, want ff02::1", multicast6Group)
	}
}

// write sends every unicast destination, IPv4 or IPv6, through the dual-stack base socket; the
// IPv6 wrapper is reserved for multicast sends.
func TestWriteSendsThroughBaseSocket(t *testing.T) {
	base := &recordPacketConn{}
	l := &Listener{conf: ListenConfig{NetworkID: 1}, conn: base, conn6: &fakeMulticast6{}}

	v4Dst := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 255), Port: DefaultPort}
	v6Dst := &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: DefaultPort}
	if err := l.write(&RequestPacket{}, v4Dst); err != nil {
		t.Fatalf("write v4: %v", err)
	}
	if err := l.write(&RequestPacket{}, v6Dst); err != nil {
		t.Fatalf("write v6: %v", err)
	}
	if len(base.writes) != 2 || base.writes[0] != v4Dst || base.writes[1] != v6Dst {
		t.Fatalf("base socket writes = %v, want [%v %v]", base.writes, v4Dst, v6Dst)
	}
}

// A dual-stack socket joins ff02::1 in both roles, so a responder bound to the well-known port
// receives IPv6 requests and a discoverer sends and receives them. This is the fix for a responder
// that previously opened no IPv6 socket at all.
func TestListenJoinsIPv6OnDualStackSocket(t *testing.T) {
	d, err := (ListenConfig{}).Listen("")
	if err != nil {
		t.Fatalf("Listen(discoverer): %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	if !dualStack(t, d) {
		t.Skip("host has no usable IPv6")
	}
	if d.conn6 == nil {
		t.Fatal("dual-stack discoverer did not join the IPv6 group")
	}

	r, err := (ListenConfig{}).Listen(net.JoinHostPort("", strconv.Itoa(DefaultPort)))
	if err != nil {
		t.Skipf("cannot bind responder on port %d: %v", DefaultPort, err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if r.directedBroadcast {
		t.Fatal("responder on the well-known port acts as a discoverer")
	}
	if dualStack(t, r) && r.conn6 == nil {
		t.Fatal("dual-stack responder did not join the IPv6 group")
	}
}

// dualStack reports whether the Listener's socket is bound to an IPv6-capable address.
func dualStack(t *testing.T, l *Listener) bool {
	t.Helper()
	local, ok := l.conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("local address = %T, want *net.UDPAddr", l.conn.LocalAddr())
	}
	return local.IP.To4() == nil
}

// recordPacketConn records the destinations written to it and drops the payload.
type recordPacketConn struct {
	net.PacketConn
	writes []net.Addr
}

func (c *recordPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	c.writes = append(c.writes, addr)
	return len(b), nil
}
