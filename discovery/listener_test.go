package discovery

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
)

func TestDiscoveryListen(t *testing.T) {
	networkID := rand.Uint64()
	listener, err := net.ListenUDP("udp", &net.UDPAddr{
		Port: 7551,
	})
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		buf := make([]byte, 1024)
		n, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			panic(err)
		}
		b := buf[:n]
		pk, senderID, err := Unmarshal(b)
		if err != nil {
			panic(err)
		}
		t.Logf("%#v %d %s", pk, senderID, addr)

		if _, ok := pk.(*RequestPacket); ok {
			data, _ := (&ServerData{
				ServerName:     "df-mc/go-nethernet",
				LevelName:      "Bedrock World",
				GameType:       2,
				PlayerCount:    1,
				MaxPlayerCount: 8,
				TransportLayer: 2, // NetherNet
				ConnectionType: 4, // LAN
			}).MarshalBinary()
			resp := &ResponsePacket{
				ApplicationData: data,
			}
			if _, err := listener.WriteToUDP(Marshal(resp, networkID), addr); err != nil {
				t.Fatalf("error sending response: %s", err)
			}
			t.Logf("responded to Request packet")
		} else if pk, ok := pk.(*MessagePacket); ok && pk.Data != "Ping" {
			t.Log(pk.Data)
		}
	}
}

func TestDiscovery(t *testing.T) {
	networkID := rand.Uint64()
	request := Marshal(&RequestPacket{}, networkID)

	listener, err := net.ListenUDP("udp", nil)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	go func() {
		ticker := time.NewTicker(time.Second)
		t.Cleanup(ticker.Stop)

		for range ticker.C {
			if n, err := listener.WriteToUDP(request, &net.UDPAddr{
				IP:   net.IPv4bcast,
				Port: 7551,
			}); err != nil {
				panic(err)
			} else {
				if n != len(request) {
					t.Fatalf("request is not fully sent: %d != %d", n, len(request))
				}
			}
			t.Log("ping")
		}
	}()

	for {
		buf := make([]byte, 1024)
		n, addr, err := listener.ReadFromUDP(buf)
		if err != nil {
			panic(err)
		}
		b := buf[:n]
		pk, senderID, err := Unmarshal(b)
		if err != nil {
			panic(err)
		}
		t.Logf("%#v %d %s", pk, senderID, addr)

		if pk, ok := pk.(*ResponsePacket); ok {
			if false {
				data := bytes.NewBuffer(pk.ApplicationData)

				var v uint8
				if err := binary.Read(data, binary.LittleEndian, &v); err != nil {
					t.Fatalf("error reading version: %s", err)
				} else if v != 4 {
					t.Fatalf("version mismatch: %d != 4", v)
				}
				t.Logf("version: %d", v)

				serverName, err := readBytes[uint8](data)
				if err != nil {
					t.Fatalf("error reading server name: %s", err)
				}
				t.Logf("server name: %q", serverName)

				levelName, err := readBytes[uint8](data)
				if err != nil {
					t.Fatalf("error reading level name: %s", err)
				}
				t.Logf("level name: %q", levelName)

				gameType, err := data.ReadByte()
				if err != nil {
					t.Fatalf("error reading game type: %s", err)
				}
				t.Logf("game type: %d", gameType)
				// adventure: 4, survival: 0, creative: 2

				// transport layer
				// unknown (why is it 8)
				t.Logf("%#v", data.Bytes())
			}
			data := &ServerData{}
			if err := data.UnmarshalBinary(pk.ApplicationData); err != nil {
				t.Fatal(err)
			}
			t.Logf("%#v", data)
		}
	}
}

func TestListen(t *testing.T) {
	cfg := ListenConfig{
		NetworkID: rand.Uint64(),
	}
	d, err := cfg.Listen("0.0.0.0:7551")
	if err != nil {
		t.Fatalf("error listening on discovery: %s", err)
	}
	t.Cleanup(func() {
		if err := d.Close(); err != nil {
			t.Errorf("error closing discovery: %s", err)
		}
	})
	d.ServerData(&ServerData{
		ServerName:     "df-mc/go-nethernet",
		LevelName:      "Bedrock World",
		GameType:       2,
		PlayerCount:    1,
		MaxPlayerCount: 8,
		TransportLayer: 2,
		ConnectionType: 4,
	})

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	var c nethernet.ListenConfig
	l, err := c.Listen(d)
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
