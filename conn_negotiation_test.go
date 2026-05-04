package nethernet

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func TestDialListenerTrickleICE(t *testing.T) {
	testDialListener(t, false)
}

func TestDialListenerNonTrickleICE(t *testing.T) {
	testDialListener(t, true)
}

func testDialListener(t *testing.T, disableTrickle bool) {
	t.Helper()

	client, server := newMemorySignalingPair("1", "2")
	defer client.close()
	defer server.close()

	l, err := (ListenConfig{DisableTrickleICE: disableTrickle}).Listen(server)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer l.Close()

	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	var d Dialer
	d.DisableTrickleICE = disableTrickle
	conn, err := d.DialContext(ctx, server.NetworkID(), client)
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	defer conn.Close()

	var serverConn net.Conn
	select {
	case serverConn = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("Accept() error = %v", err)
	case <-ctx.Done():
		t.Fatalf("Accept() timed out: %v", ctx.Err())
	}
	defer serverConn.Close()

	if disableTrickle {
		if got := client.signalCount(SignalTypeCandidate) + server.signalCount(SignalTypeCandidate); got != 0 {
			t.Fatalf("candidate signals = %d, want 0 for non-trickle ICE", got)
		}
	} else {
		if got := client.signalCount(SignalTypeCandidate) + server.signalCount(SignalTypeCandidate); got == 0 {
			t.Fatal("candidate signals = 0, want trickled candidates")
		}
	}

	read := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		b := make([]byte, 32)
		n, err := serverConn.Read(b)
		if err != nil {
			readErr <- err
			return
		}
		read <- b[:n]
	}()

	const payload = "hello"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	select {
	case got := <-read:
		if string(got) != payload {
			t.Fatalf("Read() = %q, want %q", got, payload)
		}
	case err := <-readErr:
		t.Fatalf("Read() error = %v", err)
	case <-ctx.Done():
		t.Fatalf("Read() timed out: %v", ctx.Err())
	}
}

type memorySignalingBus struct {
	mu        sync.RWMutex
	endpoints map[string]*memorySignaling
}

type memorySignaling struct {
	id     string
	bus    *memorySignalingBus
	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	next      int
	notifiers map[int]chan<- *Signal

	stats signalStats
}

type signalStats struct {
	mu     sync.Mutex
	counts map[string]int
}

func newMemorySignalingPair(clientID, serverID string) (*memorySignaling, *memorySignaling) {
	bus := &memorySignalingBus{endpoints: make(map[string]*memorySignaling)}
	client := newMemorySignaling(bus, clientID)
	server := newMemorySignaling(bus, serverID)
	bus.endpoints[clientID] = client
	bus.endpoints[serverID] = server
	return client, server
}

func newMemorySignaling(bus *memorySignalingBus, id string) *memorySignaling {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &memorySignaling{
		id:        id,
		bus:       bus,
		ctx:       ctx,
		cancel:    func() { cancel(net.ErrClosed) },
		notifiers: make(map[int]chan<- *Signal),
		stats: signalStats{
			counts: make(map[string]int),
		},
	}
}

func (s *memorySignaling) Signal(ctx context.Context, signal *Signal) error {
	s.recordSignal(signal.Type)
	if signal.Type == SignalTypeCandidate {
		time.Sleep(time.Millisecond)
	}

	s.bus.mu.RLock()
	peer := s.bus.endpoints[signal.NetworkID]
	s.bus.mu.RUnlock()
	if peer == nil {
		return fmt.Errorf("no endpoint found for network ID %q", signal.NetworkID)
	}

	delivered := *signal
	delivered.NetworkID = s.id
	return peer.deliver(ctx, &delivered)
}

func (s *memorySignaling) Notify(ch chan<- *Signal) func() {
	s.mu.Lock()
	id := s.next
	s.next++
	s.notifiers[id] = ch
	s.mu.Unlock()

	return func() {
		s.mu.Lock()
		delete(s.notifiers, id)
		s.mu.Unlock()
	}
}

func (s *memorySignaling) Context() context.Context { return s.ctx }

func (*memorySignaling) Credentials(context.Context) (*Credentials, error) { return nil, nil }

func (s *memorySignaling) NetworkID() string { return s.id }

func (*memorySignaling) PongData([]byte) {}

func (s *memorySignaling) close() { s.cancel() }

func (s *memorySignaling) deliver(ctx context.Context, signal *Signal) error {
	s.mu.Lock()
	notifiers := make([]chan<- *Signal, 0, len(s.notifiers))
	for _, ch := range s.notifiers {
		notifiers = append(notifiers, ch)
	}
	s.mu.Unlock()

	for _, ch := range notifiers {
		delivered := *signal
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.ctx.Done():
			return context.Cause(s.ctx)
		case ch <- &delivered:
		}
	}
	return nil
}

func (s *memorySignaling) recordSignal(signalType string) {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	s.stats.counts[signalType]++
}

func (s *memorySignaling) signalCount(signalType string) int {
	s.stats.mu.Lock()
	defer s.stats.mu.Unlock()
	return s.stats.counts[signalType]
}
