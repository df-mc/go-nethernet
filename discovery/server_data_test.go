package discovery

import (
	"strings"
	"testing"
)

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
