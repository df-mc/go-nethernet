package discovery

import (
	"bytes"
	"strings"
	"testing"
)

func TestServerDataMarshalBinary(t *testing.T) {
	data := testServerData("server", "world")
	data.Hardcore = true
	data.AcceptsOnlineAuth = true

	got, err := data.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	want := []byte{
		0x07,
		0x06, 's', 'e', 'r', 'v', 'e', 'r',
		0x8A, 0x22,
		0x7, '1', '.', '2', '6', '.', '5', '0',
		0x05, 'w', 'o', 'r', 'l', 'd',
		0x02,
		0x10,
		0x04,
		0x00,
		0x01,
		0x01,
		0x01,
		0x5, 'n', 'o', 'n', 'c', 'e',
		0x08,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalBinary() = % x, want % x", got, want)
	}
}

func TestServerDataUnmarshalBinary(t *testing.T) {
	var data ServerData
	if err := data.UnmarshalBinary([]byte{
		0x07,
		0x06, 's', 'e', 'r', 'v', 'e', 'r',
		0x8A, 0x22,
		0x7, '1', '.', '2', '6', '.', '5', '0',
		0x05, 'w', 'o', 'r', 'l', 'd',
		0x02,
		0x10,
		0x04,
		0x00,
		0x01,
		0x01,
		0x00,
		0x5, 'n', 'o', 'n', 'c', 'e',
		0x08,
	}); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if data.ServerName != "server" || data.LevelName != "world" || data.GameType != GameTypeAdventure {
		t.Fatalf("UnmarshalBinary() = %#v", data)
	}
	if data.Protocol != 2181 {
		t.Fatalf("protocol: %d != 2181", data.Protocol)
	}
	if data.Version != "1.26.50" {
		t.Fatalf("version: %q != \"1.26.50\"", data.Version)
	}
	if data.PlayerCount != 1 || data.MaxPlayerCount != 8 {
		t.Fatalf("UnmarshalBinary() player counts = %d/%d, want 1/8", data.PlayerCount, data.MaxPlayerCount)
	}
	if data.EditorWorld || !data.Hardcore || !data.AcceptsOnlineAuth || data.AcceptsSelfSignedAuth {
		t.Fatalf("UnmarshalBinary() bools = editor %v hardcore %v online %v self-signed %v", data.EditorWorld, data.Hardcore, data.AcceptsOnlineAuth, data.AcceptsSelfSignedAuth)
	}
	if data.ConnectionType != 4 {
		t.Fatalf("connection type: %d != 4", data.ConnectionType)
	}
}

func TestServerDataMarshalBinaryAllowsLongVarintStrings(t *testing.T) {
	data := testServerData(strings.Repeat("s", 300), strings.Repeat("l", 300))
	if _, err := data.MarshalBinary(); err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
}

func testServerData(serverName, levelName string) *ServerData {
	return &ServerData{
		ServerName:            serverName,
		Protocol:              2181,
		Version:               "1.26.50",
		LevelName:             levelName,
		GameType:              GameTypeAdventure,
		PlayerCount:           1,
		MaxPlayerCount:        8,
		AcceptsSelfSignedAuth: true,
		ConnectionType:        4,
		Nonce:                 "nonce",
	}
}
