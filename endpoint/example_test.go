package endpoint

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/df-mc/go-nethernet"
)

// ExampleClient demonstrates how to connect to a NetherNet server using HTTP signaling.
func ExampleClient() {
	// Create a signaling client.
	// This client is responsible for exchanging WebRTC connection details with the server over HTTP.
	client := NewClient()

	// Establish a NetherNet connection using the client for the signaling.
	var d nethernet.Dialer
	conn, err := d.DialContext(context.TODO(), "https://localhost:19132", client)
	if err != nil {
		panic(fmt.Sprintf("error connecting to server: %s", err))
	}
	defer conn.Close()

	fmt.Printf("connected, latency: %s", conn.Latency())
}

// ExampleHandler demonstrates how to expose a NetherNet listener using HTTP/TLS server
// for signaling.
func ExampleHandler() {
	handler, err := Serve(":19132")
	if err != nil {
		panic(fmt.Sprintf("error listening on HTTP: %s", err))
	}
	defer handler.Close()

	// Set up a NetherNet listener.
	var cfg nethernet.ListenConfig
	l, err := cfg.Listen(handler)
	if err != nil {
		panic(fmt.Sprintf("error listening on NetherNet: %s", err))
	}
	defer l.Close()

	// Start accepting NetherNet connections.
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
}

// ExampleClient_Status demonstrates how to retrieve a status for a NetherNet server.
func ExampleClient_Status() {
	// Create a client.
	client := NewClient()

	// Query the server status at the specific address. The address can be an HTTP or HTTPS URL with a port number.
	status, err := client.Status(context.TODO(), "http://127.0.0.1:19132")
	if err != nil {
		panic(err)
	}

	fmt.Println(strconv.Quote(status.ServerName)) // "Dedicated Server"
}
