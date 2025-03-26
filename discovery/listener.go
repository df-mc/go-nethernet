package discovery

import (
	"context"
	"errors"
	"fmt"
	"github.com/df-mc/go-nethernet"
	"log/slog"
	"maps"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
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

		notifiers: make(map[uint32]nethernet.Notifier),

		closed: make(chan struct{}),
	}
	go l.listen()

	if conf.BroadcastAddress == nil {
		l.conf.BroadcastAddress, err = broadcastAddress()
		if err != nil {
			conf.Log.Error("error resolving address for broadcast: local rooms may not be returned", slog.Any("error", err))
		}
	}
	go l.background()

	return l, nil
}

func broadcastAddress() (net.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addresses {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP.To4()
			if ip == nil {
				continue
			}
			if ipNet.IP.IsPrivate() || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
				continue
			}

			broadcast := make(net.IP, 4)
			for j := 0; j < 4; j++ {
				broadcast[j] = ip[j] | ^ipNet.Mask[j]
			}
			return &net.UDPAddr{IP: broadcast, Port: 7551}, nil
		}
	}
	return nil, fmt.Errorf("no suitable broadcast address found")
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

func (l *Listener) Notify(n nethernet.Notifier) func() {
	l.notifiersMu.Lock()
	i := l.notifyCount
	l.notifiers[i] = n
	l.notifyCount++
	l.notifiersMu.Unlock()

	return func() {
		l.notifiersMu.Lock()
		l.stop(i, n)
		l.notifiersMu.Unlock()
	}
}

func (l *Listener) stop(i uint32, n nethernet.Notifier) {
	n.NotifyError(nethernet.ErrSignalingStopped)

	delete(l.notifiers, i)
}

func (l *Listener) Credentials(context.Context) (*nethernet.Credentials, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, nil
	}
}

func (l *Listener) NetworkID() uint64 {
	return l.conf.NetworkID
}

func (l *Listener) Responses() map[uint64][]byte {
	l.responsesMu.Lock()
	defer l.responsesMu.Unlock()
	return maps.Clone(l.responses)
}

func (l *Listener) listen() {
	for {
		b := make([]byte, 1024)
		n, addr, err := l.conn.ReadFrom(b)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				l.conf.Log.Error("error reading from conn", slog.Any("error", err))
			}
			close(l.closed)
			return
		}
		if err := l.handlePacket(b[:n], addr); err != nil {
			l.conf.Log.Error("error handling packet", slog.Any("error", err), "from", addr)
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
	l.pongData.Store(&b)
}

func (l *Listener) PongData(b []byte) {
	parts := strings.Split(string(b), ";")
	if len(parts) < 9 {
		l.conf.Log.Error("unexpected pong data format", slog.String("data", string(b)))
		return
	}
	players, _ := strconv.Atoi(parts[4])
	maxPlayers, _ := strconv.Atoi(parts[5])
	d := &ServerData{
		Version:        0x03,
		ServerName:     parts[1],
		LevelName:      parts[7],
		GameType:       0, // TODO: Parse from parts[8] (survival, creative...)
		PlayerCount:    int32(players),
		MaxPlayerCount: int32(maxPlayers),
		EditorWorld:    false,
		Hardcore:       false,
		TransportLayer: 2,
	}
	l.ServerData(d)
}

func (l *Listener) Close() (err error) {
	l.once.Do(func() {
		err = l.conn.Close()

		l.notifiersMu.Lock()
		for i, n := range l.notifiers {
			l.stop(i, n)
		}
		l.notifiersMu.Unlock()
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
						l.conf.Log.Error("error broadcasting request", slog.Any("error", err))
					}
				}
			}
		}
	}
}

func (l *Listener) deleteInactiveAddresses() {
	l.addressesMu.Lock()
	maps.DeleteFunc(l.addresses, func(_ uint64, a address) bool {
		return time.Since(a.t) > time.Second*15
	})
	l.addressesMu.Unlock()
}

func (l *Listener) write(b []byte, addr net.Addr) (n int, err error) {
	if remote, ok := l.addrPort(addr); ok {
		if local, ok := l.addrPort(l.conn.LocalAddr()); ok {
			if remote.Addr().Compare(local.Addr()) == 0 {
				bcast, err := broadcastAddress()
				if err != nil {
					l.conf.Log.Error("error resolving broadcast address", slog.Any("addr", addr), slog.Any("error", err))
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
