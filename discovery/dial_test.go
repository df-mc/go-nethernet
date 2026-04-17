//go:build manual

package discovery

import (
	"context"
	"math/rand/v2"
	"strconv"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

// TestDial demonstrates a client connecting to the host.
func TestDial(t *testing.T) {
	cfg := ListenConfig{
		NetworkID: rand.Uint64(),
	}
	d, err := cfg.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			var (
				serverData = &ServerData{}
				networkID  uint64
			)
			for id, response := range d.Responses() {
				if err := serverData.UnmarshalBinary(response); err != nil {
					t.Errorf("error decoding server data: %s", err)
				}
				networkID = id
				goto FOUND
			}
			continue
		FOUND:
			t.Logf("Found host: %q (%s)", serverData.LevelName, serverData.ServerName)
			dial(t, networkID, d, serverData)
			return
		case <-t.Context().Done():
			return
		}
	}
}

func dial(t testing.TB, networkID uint64, signaling nethernet.Signaling, serverData *ServerData) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second*15)
	defer cancel()

	var d nethernet.Dialer
	conn, err := d.DialContext(ctx, strconv.FormatUint(networkID, 10), signaling)
	if err != nil {
		t.Fatalf("error connecting to %s: %s", serverData.ServerName, err)
	}
	defer conn.Close()

	t.Logf("connected, latency: %s", conn.Latency())
}
