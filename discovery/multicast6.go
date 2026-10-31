package discovery

import (
	"errors"
	"log/slog"
	"net"

	"golang.org/x/net/ipv6"
)

// multicast6Group is the IPv6 all-nodes link-local multicast group vanilla discovers LAN games on.
var multicast6Group = net.ParseIP("ff02::1")

// multicast6Conn is the part of *ipv6.PacketConn the discovering role drives, so the join and send
// paths can be exercised without opening a real socket.
type multicast6Conn interface {
	JoinGroup(ifi *net.Interface, group net.Addr) error
	SetMulticastInterface(ifi *net.Interface) error
	WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error)
	ReadFrom(b []byte) (n int, cm *ipv6.ControlMessage, src net.Addr, err error)
	Close() error
}

var _ multicast6Conn = (*ipv6.PacketConn)(nil)

// openMulticast6 opens the [::] IPv6 socket a discovering Listener uses and joins the all-nodes group on
// every usable interface, as vanilla opens its socket regardless of the interfaces present. It returns
// nil, leaving IPv4 discovery to run alone, only when the host has no IPv6 support and the bind fails.
// The socket is kept for the Listener's life; sends pick up interfaces that appear later, since
// broadcastRequest6 re-enumerates them every tick like the IPv4 side.
func openMulticast6(log *slog.Logger) multicast6Conn {
	conn, err := net.ListenPacket("udp6", net.JoinHostPort("::", "0"))
	if err != nil {
		log.Debug("error opening IPv6 discovery socket", slog.Any("error", err))
		return nil
	}
	p := ipv6.NewPacketConn(conn)
	joinMulticast6(p, multicast6Interfaces(), log)
	return p
}

// joinMulticast6 joins the all-nodes group on each interface, logging and skipping any that fails, and
// returns how many joined. A send still reaches a group without membership, so a zero count is not fatal.
func joinMulticast6(conn multicast6Conn, ifaces []net.Interface, log *slog.Logger) int {
	group := &net.IPAddr{IP: multicast6Group}
	var joined int
	for i := range ifaces {
		if err := conn.JoinGroup(&ifaces[i], group); err != nil {
			log.Debug("error joining IPv6 discovery group", slog.String("interface", ifaces[i].Name), slog.Any("error", err))
			continue
		}
		joined++
	}
	return joined
}

// broadcastRequest6 multicasts a RequestPacket to [ff02::1]:7551 out of every usable IPv6 interface.
func (l *Listener) broadcastRequest6() {
	sendMulticast6Requests(l.conn6, Marshal(&RequestPacket{}, l.conf.NetworkID), multicast6Interfaces(), l.conf.Log)
}

// sendMulticast6Requests writes b to [ff02::1]:7551 on each interface in turn, selecting the outgoing
// interface per send. A failure on one interface is logged and does not stop the rest.
func sendMulticast6Requests(conn multicast6Conn, b []byte, ifaces []net.Interface, log *slog.Logger) {
	dst := &net.UDPAddr{IP: multicast6Group, Port: DefaultPort}
	for i := range ifaces {
		if err := conn.SetMulticastInterface(&ifaces[i]); err != nil {
			log.Debug("error selecting IPv6 multicast interface", slog.String("interface", ifaces[i].Name), slog.Any("error", err))
			continue
		}
		if _, err := conn.WriteTo(b, nil, dst); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Debug("error broadcasting request to IPv6 group", slog.String("interface", ifaces[i].Name), slog.Any("error", err))
		}
	}
}

// listen6 reads responses on the IPv6 socket into the same handler path as IPv4 until the Listener closes.
func (l *Listener) listen6() {
	b := make([]byte, maxUDPPacketSize)
	for {
		n, _, addr, err := l.conn6.ReadFrom(b)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				l.conf.Log.Error("error reading from IPv6 conn", slog.Any("error", err))
			}
			_ = l.Close()
			return
		}
		if err := l.handlePacket(b[:n], addr); err != nil {
			l.conf.Log.Error("error handling packet", slog.Any("error", err), "from", addr)
		}
	}
}

// multicast6Interfaces returns the up, multicast-capable, non-loopback interfaces that hold an IPv6
// address. It returns none when the host has no usable IPv6.
func multicast6Interfaces() []net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Interface
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if supportsMulticast6(iface.Flags, addrs) {
			out = append(out, iface)
		}
	}
	return out
}

// supportsMulticast6 reports whether an interface with these flags and addresses can carry IPv6
// multicast discovery: up, multicast-capable, not loopback, and holding an IPv6 address.
func supportsMulticast6(flags net.Flags, addrs []net.Addr) bool {
	if flags&net.FlagUp == 0 || flags&net.FlagMulticast == 0 || flags&net.FlagLoopback != 0 {
		return false
	}
	for _, addr := range addrs {
		if network, ok := addr.(*net.IPNet); ok && network.IP.To4() == nil && network.IP.To16() != nil {
			return true
		}
	}
	return false
}

// isIPv6Addr reports whether addr is a UDP address that is IPv6 rather than IPv4.
func isIPv6Addr(addr net.Addr) bool {
	udp, ok := addr.(*net.UDPAddr)
	return ok && udp.IP.To4() == nil && udp.IP.To16() != nil
}
