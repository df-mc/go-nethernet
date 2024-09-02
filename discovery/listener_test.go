package discovery

import (
	"errors"
	"github.com/df-mc/go-nethernet"
	"math/rand"
	"net"
	"testing"
)

func TestListen(t *testing.T) {
	cfg := ListenConfig{
		NetworkID: rand.Uint64(),
	}
	d, err := cfg.Listen("udp", ":7551")
	if err != nil {
		t.Fatalf("error listening on discovery: %s", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("error closing discovery: %s", err)
		}
	})

	var c nethernet.ListenConfig
	l, err := c.Listen(cfg.NetworkID, d)
	if err != nil {
		t.Fatalf("error listening: %s", err)
	}
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Fatalf("error closing: %s", err)
		}
	})

	for {
		conn, err := l.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("error accepting connection: %s", err)
			}
			return
		}
		t.Logf("accepted: %s", conn.RemoteAddr())
	}
}
