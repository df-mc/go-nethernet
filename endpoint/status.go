package endpoint

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

// Status represents a server status of a NetherNet server.
type Status struct {
	// ServerName is the name of the server. It is displayed as the MOTD.
	ServerName string `json:"name"`
	// Protocol is the protocol version used by the upstream game listener.
	Protocol int `json:"protocol"`
	// Version is the version of the game that the server is currently running.
	Version string `json:"version"`
	// LevelName is the name of the world. It is never displayed in the server card in Multiplayer tab.
	LevelName string `json:"level"`
	// PlayerCount is the number of players that is currently connected to the server.
	PlayerCount int `json:"players"`
	// MaxPlayerCount is the number of players that can be connected to the server.
	MaxPlayerCount int `json:"maxPlayers"`
	// GameType represents the game mode of the level running in the server in numerical value.
	// It is 0 for survival, 1 for creative, and 2 for adventure.
	GameType int `json:"gameType"`
}

// RakNetPongData produces a RakNet-compatible pong data from the status.
// It is typically used for maintaining compatibility with older code that
// still expects the same format used in RakNet servers. The port included
// in the resulting data is always 19132.
func (s Status) RakNetPongData() []byte {
	var gameType string
	switch s.GameType {
	case GameTypeSurvival:
		gameType = "Survival"
	case GameTypeCreative:
		gameType = "Creative"
	case GameTypeAdventure:
		gameType = "Adventure"
	default:
		gameType = "Unknown" //
	}
	return []byte(fmt.Sprintf("MCPE;%s;%d;%s;%d;%d;%d;%s;%s;%d;%d;%d;%d;",
		s.ServerName, s.Protocol, s.Version, s.PlayerCount, s.MaxPlayerCount,
		rand.Int64(), s.LevelName, gameType, s.GameType, 19132, 19132, 0,
	))
}

// RakNetPongData parses a RakNet-compatible pong data into a Status.
// It is typically used for maintaining compatibility with older code that
// still produces the same format used in RakNet servers, e.g. Gophertunnel.
// It is also used in [Handler.PongData] in order to synchronize the status
// with the upstream Minecraft listener.
func RakNetPongData(b []byte) (Status, error) {
	frag := strings.Split(string(b), ";")
	if len(frag) < 9 {
		return Status{}, fmt.Errorf("malformed pong data: %s", b)
	}
	serverName := frag[1]
	protocol, err := strconv.Atoi(frag[2])
	if err != nil {
		return Status{}, fmt.Errorf("parse protocol version: %w", err)
	}
	version := frag[3]
	playerCount, err := strconv.Atoi(frag[4])
	if err != nil {
		return Status{}, fmt.Errorf("parse player count: %w", err)
	}
	maxPlayerCount, err := strconv.Atoi(frag[5])
	if err != nil {
		return Status{}, fmt.Errorf("parse max player count: %w", err)
	}
	levelName := frag[7]
	gameType, ok := parseGameType(frag[8])
	if !ok {
		return Status{}, fmt.Errorf("invalid game type: %q", frag[8])
	}
	return Status{
		ServerName:     serverName,
		Protocol:       protocol,
		Version:        version,
		LevelName:      levelName,
		PlayerCount:    playerCount,
		MaxPlayerCount: maxPlayerCount,
		GameType:       gameType,
	}, nil
}

// parseGameType converts the game type string from the pong data to its int32 representation.
// Returns 0 and false if the game type is not valid.
func parseGameType(v string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "survival":
		return GameTypeSurvival, true
	case "creative":
		return GameTypeCreative, true
	case "adventure":
		return GameTypeAdventure, true
	}
	return 0, false
}

const (
	GameTypeSurvival = iota
	GameTypeCreative
	GameTypeAdventure
)
