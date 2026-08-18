package discovery

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/df-mc/go-nethernet"
)

func ExampleListen() {
	cfg := ListenConfig{
		NetworkID: rand.Uint64(),
	}
	d, err := cfg.Listen("0.0.0.0:7551")
	if err != nil {
		panic(fmt.Sprintf("error listening on discovery: %s", err))
	}
	defer d.Close()

	nonce := make([]byte, 16)
	if _, err := cryptorand.Read(nonce); err != nil {
		panic(fmt.Sprintf("error generating nonce: %s", err))
	}
	d.ServerData(&ServerData{
		ServerName:            "df-mc/go-nethernet",
		LevelName:             "Bedrock World",
		GameType:              GameTypeAdventure,
		PlayerCount:           1,
		MaxPlayerCount:        8,
		AcceptsOnlineAuth:     true,
		AcceptsSelfSignedAuth: true,
		Nonce:                 hex.EncodeToString(nonce),
		TransportLayer:        TransportLayerNetherNet,
		ConnectionType:        4,
	})

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	var c nethernet.ListenConfig
	l, err := c.Listen(d)
	if err != nil {
		panic(fmt.Sprintf("error listening on NetherNet: %s", err))
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				panic(fmt.Sprintf("error accepting connection: %s", err))
			}
			return
		}
		slog.Info("connected",
			"localAddr", conn.LocalAddr(),
			"remoteAddr", conn.RemoteAddr(),
			"latency", conn.(*nethernet.Conn).Latency(),
		)
		time.AfterFunc(time.Second*5, func() {
			if err := conn.Close(); err != nil {
				panic(err)
			}
		})
	}
}
