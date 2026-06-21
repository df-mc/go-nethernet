package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
)

// debug indicates whether to show debug log in the output.
var debug = flag.Bool("debug", true, "Show debug log")

// init parses the flags given by the user in the command line.
func init() {
	flag.Parse()

	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <address:port> [cert.pem] [key.pem]\n", os.Args[0])
		flag.PrintDefaults()
	}
	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
}

// main is a program demonstrates a server connecting to a client.
func main() {
	var (
		address  = flag.Arg(0)
		certFile = flag.Arg(1)
		keyFile  = flag.Arg(2)
	)
	if address == "" {
		flag.Usage()
		os.Exit(1)
	}

	if (certFile != "") != (keyFile != "") {
		flag.Usage()
		slog.Error("either certificate or key file is missing")
		os.Exit(1)
	}

	server := endpoint.NewHandler()
	l, err := nethernet.ListenConfig{
		// The example client does not send an identity assertion, so this
		// endpoint server opts into anonymous/offline connections explicitly.
		AllowAnonymous:    true,
		DisableTrickleICE: true,
	}.Listen(server)
	if err != nil {
		panic(fmt.Sprintf("error listening on NetherNet: %s", err))
	}
	defer slog.Info("server closed")
	defer l.Close()

	tcp, err := net.Listen("tcp", address)
	if err != nil {
		panic(fmt.Sprintf("error listening on TCP: %s", err))
	}
	defer tcp.Close()

	enableTLS := certFile != "" && keyFile != ""
	srv := &http.Server{Addr: address, Handler: server}
	go func() {
		var err error
		if enableTLS {
			err = srv.ServeTLS(tcp, certFile, keyFile)
		} else {
			// We still support listening on plain HTTP to allow use of reverse proxy like Caddy.
			slog.Warn("listening on plain HTTP. vanilla clients may not be able to connect this server as it always attempt to connect with HTTPS")
			err = srv.Serve(tcp)
		}
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Sprintf("error accepting on HTTP: %s", err))
		}
	}()
	defer srv.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Kill, os.Interrupt)
	defer cancel()
	go func() {
		<-ctx.Done()
		if err := l.Close(); err != nil {
			panic(fmt.Sprintf("error closing NetherNet listener: %s", err))
		}
	}()

	slog.Info("listening on NetherNet", "address", tcp.Addr(), "https", enableTLS)

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
