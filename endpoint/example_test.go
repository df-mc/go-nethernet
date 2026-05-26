package endpoint

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"

	"github.com/df-mc/go-nethernet"
)

func ExampleClient() {
	client := NewClient(&url.URL{
		Scheme: "http",
		Host:   ":19132",
	})

	conn, err := nethernet.Dialer{
		DisableTrickleICE: true,
	}.DialContext(context.TODO(), strconv.FormatUint(rand.Uint64(), 10), client)
	if err != nil {
		panic(fmt.Sprintf("error connecting to server: %s", err))
	}
	defer conn.Close()

	fmt.Printf("connected, latency: %s", conn.Latency())
}

func ExampleServer() {
	server := NewServer()

	l, err := nethernet.ListenConfig{
		DisableTrickleICE: true,
	}.Listen(server)
	if err != nil {
		panic(fmt.Sprintf("error listening on NetherNet: %s", err))
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			fmt.Printf("connected, latency: %s\n", conn.(*nethernet.Conn).Latency())
		}
	}()

	_ = http.ListenAndServeTLS(":19132", "/path/to/cert-file", "/path/to/key-file", server)
}
