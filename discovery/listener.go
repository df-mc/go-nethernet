package discovery

import (
	"errors"
	"fmt"
	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/internal"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

type ListenConfig struct {
	NetworkID        uint64
	BroadcastAddress net.Addr
	Log              *slog.Logger
}

func (conf ListenConfig) Listen(network string, addr string) (*Listener, error) {
	if conf.Log == nil {
		conf.Log = slog.Default()
	}
	if conf.NetworkID == 0 {
		conf.NetworkID = rand.Uint64()
	}
	conn, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		conn: conn,

		conf: conf,

		addresses: make(map[uint64]address),

		closed: make(chan struct{}),
	}
	go l.listen()

	if conf.BroadcastAddress == nil {
		conf.BroadcastAddress, err = broadcastAddress(conn.LocalAddr())
		if err != nil {
			conf.Log.Error("error resolving address for broadcast: local rooms may not be returned")
		}
	}
	go l.background()

	return l, nil
}

func broadcastAddress(addr net.Addr) (net.Addr, error) {
	switch addr := addr.(type) {
	case *net.UDPAddr:
		ip := addr.IP.To4()
		if ip == nil {
			return nil, fmt.Errorf("address %q is not an IPv4 address; broadcasting on non-IPv4 address is currently not supported", addr)
		}
		return &net.UDPAddr{
			IP:   broadcast(ip),
			Port: addr.Port,
		}, nil
	case *net.TCPAddr:
		ip := addr.IP.To4()
		if ip == nil {
			return nil, fmt.Errorf("address %q is not an IPv4 address; broadcasting on non-IPv4 address is currently not supported", addr)
		}
		return &net.TCPAddr{
			IP:   broadcast(ip),
			Port: addr.Port,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported address type %T", addr)
	}
}

func broadcast(ip net.IP) net.IP {
	mask := ip.DefaultMask()
	bcast := make(net.IP, len(ip))
	for i := range len(bcast) {
		bcast[i] = ip[i] | ^mask[i]
	}
	return bcast
}

type Listener struct {
	conn net.PacketConn

	conf ListenConfig

	pongData atomic.Pointer[[]byte]

	addressesMu sync.RWMutex
	addresses   map[uint64]address

	notifyCount uint32
	notifiers   map[uint32]nethernet.Notifier
	notifiersMu sync.RWMutex

	responsesMu sync.RWMutex
	responses   map[uint64][]byte

	closed chan struct{}
	once   sync.Once
}

func (l *Listener) Signal(signal *nethernet.Signal) error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
		l.addressesMu.RLock()
		addr, ok := l.addresses[signal.NetworkID]
		l.addressesMu.RUnlock()

		if !ok {
			return fmt.Errorf("no address found for network ID: %d", signal.NetworkID)
		}

		_, err := l.write(Marshal(&MessagePacket{
			RecipientID: signal.NetworkID,
			Data:        signal.String(),
		}, l.conf.NetworkID), addr.addr)
		return err
	}
}

func (l *Listener) Notify(cancel <-chan struct{}, n nethernet.Notifier) {
	l.notifiersMu.Lock()
	i := l.notifyCount
	l.notifiers[i] = n
	l.notifyCount++
	l.notifiersMu.Unlock()

	go l.notify(cancel, n, i)
}

func (l *Listener) notify(cancel <-chan struct{}, n nethernet.Notifier, i uint32) {
	select {
	case <-l.closed:
		n.NotifyError(net.ErrClosed)
	case <-cancel:
		n.NotifyError(nethernet.ErrSignalingCanceled)
	}

	l.notifiersMu.Lock()
	delete(l.notifiers, i)
	l.notifiersMu.Unlock()
}

func (l *Listener) Credentials() (*nethernet.Credentials, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, nil
	}
}

func (l *Listener) Responses() map[uint64][]byte {
	l.responsesMu.Lock()
	defer l.responsesMu.Unlock()
	return l.responses
}

func (l *Listener) listen() {
	for {
		b := make([]byte, 1024)
		n, addr, err := l.conn.ReadFrom(b)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				l.conf.Log.Error("error reading from conn", internal.ErrAttr(err))
			}
			close(l.closed)
			return
		}
		if err := l.handlePacket(b[:n], addr); err != nil {
			l.conf.Log.Error("error handling packet", internal.ErrAttr(err), "from", addr)
		}
	}
}

func (l *Listener) handlePacket(data []byte, addr net.Addr) error {
	pk, senderID, err := Unmarshal(data)
	if err != nil {
		return fmt.Errorf("decode: %w", err)
	}

	if senderID == l.conf.NetworkID {
		return nil
	}

	l.addressesMu.Lock()
	a, ok := l.addresses[senderID]
	if !ok {
		a = address{
			networkID: senderID,
			addr:      addr,
		}
	}
	a.t = time.Now()
	l.addresses[senderID] = a
	l.addressesMu.Unlock()

	switch pk := pk.(type) {
	case *RequestPacket:
		err = l.handleRequest(addr)
	case *ResponsePacket:
		err = l.handleResponse(pk, senderID)
	case *MessagePacket:
		err = l.handleMessage(pk, senderID)
	default:
		err = fmt.Errorf("unknown packet: %T", pk)
	}

	return err
}

func (l *Listener) handleRequest(addr net.Addr) error {
	data := l.pongData.Load()
	if data == nil {
		return errors.New("application data not set yet")
	}
	if _, err := l.write(Marshal(&ResponsePacket{
		ApplicationData: *data,
	}, l.conf.NetworkID), addr); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

func (l *Listener) handleResponse(pk *ResponsePacket, senderID uint64) error {
	l.responsesMu.Lock()
	l.responses[senderID] = pk.ApplicationData
	l.responsesMu.Unlock()

	return nil
}

func (l *Listener) handleMessage(pk *MessagePacket, senderID uint64) error {
	if pk.Data == "Ping" {
		return nil
	}

	signal := &nethernet.Signal{}
	if err := signal.UnmarshalText([]byte(pk.Data)); err != nil {
		return fmt.Errorf("decode signal: %w", err)
	}
	signal.NetworkID = senderID

	l.notifiersMu.Lock()
	for _, n := range l.notifiers {
		n.NotifySignal(signal)
	}
	l.notifiersMu.Unlock()

	return nil
}

func (l *Listener) ServerData(d *ServerData) {
	b, _ := d.MarshalBinary()
	l.PongData(b)
}

func (l *Listener) PongData(b []byte) { l.pongData.Store(&b) }

func (l *Listener) Close() (err error) {
	l.once.Do(func() {
		err = l.conn.Close()
	})
	return err
}

func (l *Listener) background() {
	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	for {
		select {
		case <-l.closed:
			return
		case <-ticker.C:
			l.deleteInactiveAddresses()

			if l.conf.BroadcastAddress != nil {
				if _, err := l.conn.WriteTo(Marshal(&RequestPacket{}, l.conf.NetworkID), l.conf.BroadcastAddress); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						l.conf.Log.Error("error broadcasting request", internal.ErrAttr(err))
					}
				}
			}
		}
	}
}

func (l *Listener) deleteInactiveAddresses() {
	l.addressesMu.Lock()
	for networkID, a := range l.addresses {
		if time.Since(a.t) < time.Second*15 {
			delete(l.addresses, networkID)
		}
	}
	l.addressesMu.Unlock()
}

func (l *Listener) write(b []byte, addr net.Addr) (n int, err error) {
	if remote, ok := l.addrPort(addr); ok {
		if local, ok := l.addrPort(l.conn.LocalAddr()); ok {
			if remote.Compare(local) == 0 {
				bcast, err := broadcastAddress(addr)
				if err != nil {
					l.conf.Log.Error("error resolving broadcast address", slog.Any("addr", addr), internal.ErrAttr(err))
				} else {
					addr = bcast
				}
			}
		}
	}
	return l.conn.WriteTo(b, addr)
}

func (l *Listener) addrPort(addr net.Addr) (netip.AddrPort, bool) {
	if a, ok := addr.(interface {
		AddrPort() netip.AddrPort
	}); ok {
		return a.AddrPort(), true
	}
	return netip.AddrPort{}, false
}

type address struct {
	networkID uint64
	t         time.Time
	addr      net.Addr
}
