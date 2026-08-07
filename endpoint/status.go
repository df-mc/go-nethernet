package endpoint

import (
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
)

type Status struct {
	ServerName     string `json:"name"`
	Protocol       int    `json:"protocol"`
	Version        string `json:"version"`
	LevelName      string `json:"level"`
	PlayerCount    int    `json:"players"`
	MaxPlayerCount int    `json:"maxPlayers"`
	GameType       int    `json:"gameType"`
}

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
