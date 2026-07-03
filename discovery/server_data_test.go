package discovery

import (
	"bytes"
	"strings"
	"testing"
)

func TestServerDataMarshalBinaryV5(t *testing.T) {
	data := testServerData("server", "world")
	data.Hardcore = true
	data.AcceptsOnlineAuth = true

	got, err := data.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	want := []byte{
		0x05,
		0x06, 's', 'e', 'r', 'v', 'e', 'r',
		0x05, 'w', 'o', 'r', 'l', 'd',
		0x04,
		0x01, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00,
		0x00,
		0x01,
		0x01,
		0x01,
		0x04,
		0x08,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalBinary() = % x, want % x", got, want)
	}
}

func TestServerDataUnmarshalBinaryV5(t *testing.T) {
	var data ServerData
	if err := data.UnmarshalBinary([]byte{
		0x05,
		0x06, 's', 'e', 'r', 'v', 'e', 'r',
		0x05, 'w', 'o', 'r', 'l', 'd',
		0x04,
		0x01, 0x00, 0x00, 0x00,
		0x08, 0x00, 0x00, 0x00,
		0x00,
		0x01,
		0x01,
		0x00,
		0x04,
		0x08,
	}); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if data.ServerName != "server" || data.LevelName != "world" || data.GameType != GameTypeAdventure {
		t.Fatalf("UnmarshalBinary() = %#v", data)
	}
	if data.PlayerCount != 1 || data.MaxPlayerCount != 8 {
		t.Fatalf("UnmarshalBinary() player counts = %d/%d, want 1/8", data.PlayerCount, data.MaxPlayerCount)
	}
	if data.EditorWorld || !data.Hardcore || !data.AcceptsOnlineAuth || data.AcceptsSelfSignedAuth {
		t.Fatalf("UnmarshalBinary() bools = editor %v hardcore %v online %v self-signed %v", data.EditorWorld, data.Hardcore, data.AcceptsOnlineAuth, data.AcceptsSelfSignedAuth)
	}
	if data.TransportLayer != TransportLayerNetherNet || data.ConnectionType != 4 {
		t.Fatalf("UnmarshalBinary() transport/connection = %d/%d, want 2/4", data.TransportLayer, data.ConnectionType)
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
		LevelName:             levelName,
		GameType:              GameTypeAdventure,
		PlayerCount:           1,
		MaxPlayerCount:        8,
		AcceptsSelfSignedAuth: true,
		TransportLayer:        TransportLayerNetherNet,
		ConnectionType:        4,
	}
}
