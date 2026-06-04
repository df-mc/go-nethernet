package discovery

import (
	"strings"
	"testing"
)

func TestServerDataMarshalBinaryNameLengthBoundary(t *testing.T) {
	tests := []struct {
		name string
		data *ServerData
	}{
		{
			name: "server name",
			data: testServerData(strings.Repeat("s", maxServerDataNameLength), "world"),
		},
		{
			name: "level name",
			data: testServerData("server", strings.Repeat("l", maxServerDataNameLength)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := tt.data.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v, want nil", err)
			}

			var got ServerData
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v, want nil", err)
			}
			if got.ServerName != tt.data.ServerName {
				t.Fatalf("ServerName = %q, want %q", got.ServerName, tt.data.ServerName)
			}
			if got.LevelName != tt.data.LevelName {
				t.Fatalf("LevelName = %q, want %q", got.LevelName, tt.data.LevelName)
			}
		})
	}
}

func TestServerDataMarshalBinaryRejectsOverlongNames(t *testing.T) {
	tests := []struct {
		name string
		data *ServerData
	}{
		{
			name: "server name",
			data: testServerData(strings.Repeat("s", maxServerDataNameLength+1), "world"),
		},
		{
			name: "level name",
			data: testServerData("server", strings.Repeat("l", maxServerDataNameLength+1)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.data.MarshalBinary(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want overlong name error")
			}
		})
	}
}

func TestListenerServerDataDoesNotReplacePongDataOnMarshalError(t *testing.T) {
	l := &Listener{}
	l.ServerData(testServerData("server", "world"))

	before := l.pongData.Load()
	if before == nil {
		t.Fatal("pongData was not set by valid server data")
	}

	l.ServerData(testServerData(strings.Repeat("s", maxServerDataNameLength+1), "world"))
	after := l.pongData.Load()
	if after != before {
		t.Fatal("pongData was replaced after MarshalBinary error")
	}
}

func testServerData(serverName, levelName string) *ServerData {
	return &ServerData{
		ServerName:     serverName,
		LevelName:      levelName,
		GameType:       2,
		PlayerCount:    1,
		MaxPlayerCount: 8,
		TransportLayer: 2,
		ConnectionType: 4,
	}
}
