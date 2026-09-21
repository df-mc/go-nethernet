package endpoint

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/df-mc/go-nethernet"
)

func TestSignalVanillaEmitsVanillaHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	raw := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8192)
		n, _ := conn.Read(buf)
		raw <- string(buf[:n])
		// Minimal SDP answer response.
		conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/sdp\r\nContent-Length: 7\r\nConnection: close\r\n\r\nanswer!"))
	}()

	client := ClientConfig{NetworkID: "123"}.New()
	stop := client.Notify(notifierFunc(func(*nethernet.Signal) {}))
	defer stop()

	addr := "http://" + ln.Addr().String()
	if err := client.Signal(context.Background(), &nethernet.Signal{
		Type:         nethernet.SignalTypeOffer,
		ConnectionID: 1,
		NetworkID:    addr,
		Data:         "offer-body",
	}); err != nil {
		t.Fatalf("Signal: %v", err)
	}
	got := <-raw
	lines := strings.Split(got, "\r\n")
	if lines[0] != "POST /v1/join/123 HTTP/1.1" {
		t.Fatalf("request line = %q", lines[0])
	}
	want := []string{
		"Connection: Keep-Alive",
		"Content-Type: application/sdp",
		"User-Agent: libhttpclient/1.0.0.0",
		"Content-Length: 10",
		"Host: " + ln.Addr().String(),
	}
	for i, w := range want {
		if lines[1+i] != w {
			t.Fatalf("header %d = %q, want %q\nfull:\n%s", i, lines[1+i], w, got)
		}
	}
	if strings.Contains(got, "Go-http-client") || strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("vanilla request must not contain Go UA or Accept-Encoding:\n%s", got)
	}
}
