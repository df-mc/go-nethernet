package discovery

import (
	"errors"
	"log/slog"
	"net"

	"golang.org/x/net/ipv6"
)

// multicast6Group is the IPv6 all-nodes link-local multicast group vanilla discovers LAN games on.
var multicast6Group = net.ParseIP("ff02::1")

// multicast6Conn is the subset of *ipv6.PacketConn the discovery socket drives: joining the group
// it receives requests on and sending requests out a chosen interface with loopback off. It lets
// the join and send paths be tested without a real socket.
type multicast6Conn interface {
	JoinGroup(ifi *net.Interface, group net.Addr) error
	SetMulticastInterface(ifi *net.Interface) error
	SetMulticastLoopback(bool) error
	WriteTo(b []byte, cm *ipv6.ControlMessage, dst net.Addr) (int, error)
}

var _ multicast6Conn = (*ipv6.PacketConn)(nil)

// newMulticast6 wraps the Listener's dual-stack socket for IPv6 multicast and configures it with
// [setupMulticast6]. The wrapper shares the socket's file descriptor, so it is not closed
// separately. The group is joined once here; an interface that appears later is used for sending
// but not re-joined for receiving.
func newMulticast6(conn net.PacketConn, log *slog.Logger) *ipv6.PacketConn {
	p := ipv6.NewPacketConn(conn)
	setupMulticast6(p, multicast6Interfaces(), log)
	return p
}

// setupMulticast6 turns multicast loopback off and joins the all-nodes group on each interface, so
// requests sent to [ff02::1]:7551 reach the socket without it also receiving its own sends.
func setupMulticast6(conn multicast6Conn, ifaces []net.Interface, log *slog.Logger) {
	if err := conn.SetMulticastLoopback(false); err != nil {
		log.Debug("error disabling IPv6 multicast loopback", slog.Any("error", err))
	}
	joinMulticast6(conn, ifaces, log)
}

// joinMulticast6 joins the all-nodes group on each interface, logging and skipping any that fails,
// and returns how many joined. A send still reaches a group without membership, so zero is not fatal.
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
