package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
)

// init parses the flags given by the user in the command line.
func init() {
	flag.Parse()
}

// main is a program that demonstrates a client connecting to
// the server over NetherNet via HTTP signaling.
func main() {
	address := flag.Arg(0)
	if address == "" {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <url>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()

	u, err := url.Parse(address)
	if err != nil {
		panic(fmt.Sprintf("error parsing URL: %s", err))
	}
	client := endpoint.NewClient(u)

	slog.Info("establishing connection over NetherNet... send an interrupt signal (Ctrl+C) to abort", "url", u)
	conn, err := nethernet.Dialer{DisableTrickleICE: true}.DialContext(ctx, client.NetworkID(), client)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	slog.Info("connected",
		"remoteAddr", conn.RemoteAddr(),
		"localAddr", conn.LocalAddr(),
		"latency", conn.Latency(),
	)

	slog.Info("disconnecting in 15 seconds...")
	select {
	case <-ctx.Done():
	case <-conn.Context().Done():
	case <-time.After(time.Second * 15):
	}
}
