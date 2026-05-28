package endpoint

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"

	"github.com/df-mc/go-nethernet"
)

// ExampleClient demonstrates how to connect to a NetherNet server using HTTP signaling.
func ExampleClient() {
	// Create a signaling client.
	// This client is responsible for exchanging WebRTC connection details with the server over HTTP.
	client := NewClient(&url.URL{
		Scheme: "http",
		Host:   ":19132",
	})

	// Establish a NetherNet connection using the client for the signaling.
	var d nethernet.Dialer
	conn, err := d.DialContext(context.TODO(), strconv.FormatUint(rand.Uint64(), 10), client)
	if err != nil {
		panic(fmt.Sprintf("error connecting to server: %s", err))
	}
	defer conn.Close()

	fmt.Printf("connected, latency: %s", conn.Latency())
}

// ExampleServer demonstrates how to expose a NetherNet listener using HTTP/TLS server
// for signaling.
func ExampleServer() {
	server := NewHandler()

	// Set up a NetherNet listener.
	var cfg nethernet.ListenConfig
	l, err := cfg.Listen(server)
	if err != nil {
		panic(fmt.Sprintf("error listening on NetherNet: %s", err))
	}
	defer l.Close()

	// Start accepting NetherNet connections in a goroutine.
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			slog.Info("connected",
				"remoteAddr", conn.RemoteAddr(),
				"localAddr", conn.LocalAddr(),
				"latency", conn.(*nethernet.Conn).Latency(),
			)
		}
	}()

	// Start listening on HTTP/TLS. This will block until the server stops.
	// In production, it is recommended to create an [http.Server] and call its Close() method when it's done.
	_ = http.ListenAndServeTLS(":19132", "/path/to/cert-file", "/path/to/key-file", server)
}
