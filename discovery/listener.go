package discovery

import (
	"context"
	"errors"
	"fmt"
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

	"github.com/df-mc/go-nethernet"
)

type ListenConfig struct {
	// NetworkID specifies the network ID for the NetherNet network being announced to the clients in the
	// same network. In NetherNet, it is explicitly defined as a string, but in LAN discovery it is sent as an uint8.
	NetworkID uint64

	// BroadcastAddress specifies the UDP broadcast address for sending request packets to the servers in
	// the same network. If nil, an *net.UDPAddr with net.IPv4bcast and port 7551 will be used.
	BroadcastAddress *net.UDPAddr

	// Log is used for logging messages at various levels.
	Log *slog.Logger
}

// Listen starts listening on the specified address. For servers, it should be typically composed for using port
// 7551 to respond from request packets broadcasted from clients. For clients, it can be an empty string or any
// address with any port, as it doesn't need to response with other clients; when you expect that port 7551 is
// already in use by the game itself, you might want to specify the address in this way.
func (conf ListenConfig) Listen(addr string) (*Listener, error) {
	if conf.Log == nil {
		conf.Log = slog.Default()
	}
	if conf.NetworkID == 0 {
		conf.NetworkID = rand.Uint64()
	}
	addrPort, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}
	// We hardcode network protocol for "udp" as it always expects UDP packets to be received.
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, err
	}

	if conf.BroadcastAddress == nil && addrPort.Port() != DefaultPort {
		// If the port for the address is 7551, it means no applications are listening on this network
		// and server discovery using limited broadcast on net.IPv4bcast is not meaningful.
		conf.BroadcastAddress = &net.UDPAddr{
			IP:   net.IPv4bcast,
			Port: DefaultPort,
		}
	}

	l := &Listener{
		conn: conn,

		conf: conf,

		addresses: make(map[uint64]address),

		notifiers: make(map[uint32]notifier),
		responses: make(map[uint64][]byte),

		closed: make(chan struct{}),
	}

	go l.listen()
	go l.background()

	return l, nil
}

// DefaultPort is the port used for LAN discovery in Minecraft: Bedrock Edition.
// Servers should listen on this port to receive RequestPacket broadcasted from clients.
const DefaultPort = 7551

// Listener represents a listener for LAN discovery. It uses UDP as the underlying protocol
// and allows both discovering servers on the network using broadcast or announcing servers
// to the clients in the network.
type Listener struct {
	conn net.PacketConn

	// conf is the ListenConfig used for [ListenConfig.Listen].
	conf ListenConfig

	// pongData atomically stores the application data for responding to the clients
	// broadcasting RequestPacket with a ResponsePacket containing the same data.
	// Since it is specific to applications, it is not represented in ServerData
	// and instead []byte.
	pongData atomic.Pointer[[]byte]

	// addresses stores a map whose keys are NetherNet network IDs and the value
	// is an address struct, which stores the UDP address for the NetherNet network
	// ID along with the timestamp for expiring inactivity addresses. It is guarded
	// by addressesMu for atomic access in concurrent goroutines like background and
	// handlePacket.
	addresses   map[uint64]address
	addressesMu sync.RWMutex

	// notifyCount counts the total notifiers registered for the Listener.
	// It is used as the ID for [nethernet.Notifier] and should not be decreased at all.
	// notifyCount should be atomically accessed by holding a lock on notifiersMu.
	notifyCount uint32
	notifiers   map[uint32]notifier
	notifiersMu sync.RWMutex

	// responses stores a map whose keys are NetherNet network IDs which value is an
	// application-specific data sent as ResponsePacket from the servers in the network.
	responses   map[uint64][]byte
	responsesMu sync.RWMutex

	// closed is a channel that is closed when the Listener closes.
	closed chan struct{}
	// once ensures the Listener is closed only once.
	once sync.Once
}

type notifier struct {
	in  chan *nethernet.Signal
	out chan<- *nethernet.Signal
}

// Signal sends a NetherNet signal to the corresponding address for the network ID.
func (l *Listener) Signal(ctx context.Context, signal *nethernet.Signal) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-l.closed:
		return net.ErrClosed
	default:
		networkID, err := strconv.ParseUint(signal.NetworkID, 10, 64)
		if err != nil {
			return fmt.Errorf("parse network ID as uint64: %w", err)
		}

		l.addressesMu.RLock()
		addr, ok := l.addresses[networkID]
		l.addressesMu.RUnlock()

		if !ok {
			return fmt.Errorf("no address found for network ID: %d", networkID)
		}

		return l.write(&MessagePacket{
			RecipientID: networkID,
			Data:        signal.String(),
		}, addr.addr)
	}
}

// Notify registers a channel to receive incoming NetherNet signals.
//
// The returned stop function unregisters the channel and closes it. Callers must not close
// the channel themselves.
func (l *Listener) Notify(signals chan<- *nethernet.Signal) (stop func()) {
	l.notifiersMu.Lock()
	i := l.notifyCount
	n := notifier{
		// Buffer notifications so packet handling never blocks under lock.
		in:  make(chan *nethernet.Signal, 64),
		out: signals,
	}
	l.notifiers[i] = n
	l.notifyCount++
	l.notifiersMu.Unlock()

	go func() {
		defer close(signals)
		for sig := range n.in {
			n.out <- sig
		}
	}()

	return func() {
		l.notifiersMu.Lock()
		l.stop(i)
		l.notifiersMu.Unlock()
	}
}

// Context returns a context that is canceled when the Listener is closed.
func (l *Listener) Context() context.Context {
	return listenerContext{l.closed}
}

// stop stops notifying signals on the notifier with the corresponding ID. The ID
// is internally assigned for the notifier and contained in the stop function returned
// by [Listener.Notify]. It should not be called by anywhere else.
func (l *Listener) stop(i uint32) {
	n, ok := l.notifiers[i]
	if !ok {
		return
	}
	delete(l.notifiers, i)
	close(n.in)
}

// Credentials returns a nil *nethernet.Credentials with a nil error if the Listener is not closed.
func (l *Listener) Credentials(context.Context) (*nethernet.Credentials, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	default:
		return nil, nil
	}
}

// NetworkID returns the numerical NetherNet network ID for the Listener in string form.
func (l *Listener) NetworkID() string {
	return strconv.FormatUint(l.conf.NetworkID, 10)
}

// Responses returns the responses sent from servers in the same network during LAN discovery
// using RequestPacket with the broadcast address specified in [ListenConfig.BroadcastAddress].
func (l *Listener) Responses() map[uint64][]byte {
	l.responsesMu.Lock()
	defer l.responsesMu.Unlock()
	// As Listener.responses are continuously supposed to be written by Listener.background,
	// we return a clone of the map.
	return maps.Clone(l.responses)
}

// listen continuously reads packets received in the conn and calls handlePacket.
func (l *Listener) listen() {
	for {
		b := make([]byte, 1024)
		n, addr, err := l.conn.ReadFrom(b)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				l.conf.Log.Error("error reading from conn", slog.Any("error", err))
			}
			_ = l.Close()
			return
		}
		if err := l.handlePacket(b[:n], addr); err != nil {
			l.conf.Log.Error("error handling packet", slog.Any("error", err), "from", addr)
		}
	}
}

// write writes the packet to the destination address using the network ID of Listener.
func (l *Listener) write(pk Packet, addr net.Addr) error {
	b := Marshal(pk, l.conf.NetworkID)
	_, err := l.conn.WriteTo(b, addr)
	return err
}

// handlePacket handles a packet data received from the remote network. An addr will be mapped
// for the NetherNet ID for future use in [NetherNet.Signal], if decoding was successful.
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
	// Update or set the timestamp for expiring them in deleteInactiveAddresses.
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

// handleRequest handles a RequestPacket broadcasted from the clients.
// It responds with a ResponsePacket containing the pongData if it was non-nil.
func (l *Listener) handleRequest(addr net.Addr) error {
	data := l.pongData.Load()
	if data == nil {
		return errors.New("application data not set yet")
	}
	if err := l.write(&ResponsePacket{
		ApplicationData: *data,
	}, addr); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

// handleResponse handles a ResponsePacket sent from the servers.
// It stores its ApplicationData to the responses atomically along with the sender ID.
func (l *Listener) handleResponse(pk *ResponsePacket, senderID uint64) error {
	l.responsesMu.Lock()
	l.responses[senderID] = pk.ApplicationData
	l.responsesMu.Unlock()

	return nil
}

// handleMessage handles a MessagePacket sent from the remote NetherNet network.
// It discards the packet if the Data is "Ping", otherwise decodes them as a [nethernet.Signal].
func (l *Listener) handleMessage(pk *MessagePacket, senderID uint64) error {
	if pk.Data == "Ping" {
		return nil
	}

	signal := &nethernet.Signal{}
	if err := signal.UnmarshalText([]byte(pk.Data)); err != nil {
		return fmt.Errorf("decode signal: %w", err)
	}
	signal.NetworkID = strconv.FormatUint(senderID, 10)

	l.notifiersMu.RLock()
	for _, n := range l.notifiers {
		select {
		case n.in <- signal:
		default:
			// Drop when notifier is backed up to avoid deadlocks and keep packet processing moving.
			l.conf.Log.Debug("dropping signal due to notifier being backed up", slog.String("signal", signal.String()))
		}
	}
	l.notifiersMu.RUnlock()

	return nil
}

// ServerData stores the ServerData for responding to the clients broadcasting
// RequestPacket with a ResponsePacket containing the binary representation.
func (l *Listener) ServerData(d *ServerData) {
	b, _ := d.MarshalBinary()
	l.pongData.Store(&b)
}

// PongData sets the application data contained in ResponsePacket in response
// to clients broadcasting RequestPacket. It currently decodes the data as a
// pong data from Minecraft listeners.
func (l *Listener) PongData(b []byte) {
	parts := strings.Split(string(b), ";")
	if len(parts) < 9 {
		l.conf.Log.Error("unexpected pong data format", slog.String("data", string(b)))
		return
	}
	players, _ := strconv.Atoi(parts[4])
	maxPlayers, _ := strconv.Atoi(parts[5])
	gameType, ok := parsePongGameType(parts[8])
	if !ok {
		l.conf.Log.Debug("unexpected pong game type", slog.String("gametype", parts[8]))
	}

	d := &ServerData{
		ServerName:     parts[1],
		LevelName:      parts[7],
		GameType:       gameType,
		PlayerCount:    int32(players),
		MaxPlayerCount: int32(maxPlayers),
		EditorWorld:    false,
		Hardcore:       false,
		TransportLayer: 2,
		ConnectionType: 4,
	}
	l.ServerData(d)
}

// parsePongGameType converts the game type string from the pong data to its uint8 representation.
// Returns 0 and false if the game type is not valid.
func parsePongGameType(v string) (uint8, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "survival":
		return 0, true
	case "creative":
		return 1, true
	case "adventure":
		return 2, true
	}
	return 0, false
}

// Close closes the Listener. Any notifiers registered to the Listener will be stopped.
func (l *Listener) Close() (err error) {
	l.once.Do(func() {
		close(l.closed)
		err = l.conn.Close()

		l.notifiersMu.Lock()
		for i := range l.notifiers {
			l.stop(i)
		}
		l.notifiersMu.Unlock()
	})
	return err
}

// background continuously broadcasts RequestPacket and calls deleteInactiveAddresses
// at 2 seconds interval until the Listener closes.
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
				if err := l.write(&RequestPacket{}, l.conf.BroadcastAddress); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						l.conf.Log.Error("error broadcasting request", slog.Any("error", err))
					}
				}
			}
		}
	}
}

// deleteInactiveAddresses deletes inactive addresses mapped to NetherNet IDs. It specifically
// removes if the address was not known for sending packets in the last 15 seconds.
func (l *Listener) deleteInactiveAddresses() {
	l.addressesMu.Lock()
	maps.DeleteFunc(l.addresses, func(_ uint64, a address) bool {
		return time.Since(a.t) > time.Second*15
	})
	l.addressesMu.Unlock()
}

// address encapsulates a mapping for NetherNet IDs and the UDP address responsible for sending
// packets. It is used for signaling a NetherNet network with an ID in [Listener.Signal].
type address struct {
	// networkID is the NetherNet network ID in packets sent from the addr.
	networkID uint64
	// t is the last timestamp that the packet was received from the addr with networkID.
	t time.Time
	// addr is the UDP address known for sending packets with the networkID.
	addr net.Addr
}

// listenerContext implements [context.Context] for a Listener.
type listenerContext struct{ closed <-chan struct{} }

// Deadline returns the zero [time.Time] and false, indicating that deadlines are not used.
func (listenerContext) Deadline() (zero time.Time, ok bool) {
	return zero, false
}

// Done returns a channel that is closed when the Listener has been closed.
func (ctx listenerContext) Done() <-chan struct{} {
	return ctx.closed
}

// Err returns [net.ErrClosed] if the Listener has been closed. Returns nil otherwise.
func (ctx listenerContext) Err() error {
	select {
	case <-ctx.closed:
		return net.ErrClosed
	default:
		return nil
	}
}

// Value returns nil for any key, as no values are associated with the context.
func (listenerContext) Value(any) any {
	return nil
}
