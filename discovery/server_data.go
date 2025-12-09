package discovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ServerData defines the binary structure representing worlds in Minecraft: Bedrock Edition.
// It is encapsulated in [ResponsePacket.ApplicationData] and sent in response to [RequestPacket]
// broadcasted by clients on port 7551.
type ServerData struct {
	// ServerName is the name of the server. It is typically the player name of the owner
	// hosting the server and is displayed below the LevelName in the world card.
	ServerName string
	// LevelName identifies the name of the world and appears at the top of ServerName in the world card.
	LevelName string
	// GameType is the default game mode of the world. Players receive this game mode when they
	// join. It remains unchanged during gameplay and may be updated the next time the world is hosted.
	GameType uint8
	// PlayerCount is teh amount of players currently connected to the world. Worlds
	// with a player count of 0 or less are not displayed by clients, so it should at
	// least 1 even if the server reports 0 to prevent world cards not appearing for the server.
	PlayerCount int32
	// MaxPlayerCount is the maximum amount of players allowed to join the world.
	MaxPlayerCount int32
	// EditorWorld is a value dictates if the world was created as a project in Editor Mode.
	// When enabled, the server or world card is only visible to clients in Editor Mode.
	EditorWorld bool
	// Hardcore indicates that the world is in hardcore mode. When enabled, it is common to also set
	// GameType to Survival (0) as well to reproduce expected behavior.
	Hardcore bool
	// TransportLayer indicates the transport layer used by the server. In vanilla, this is typically
	// 2 for NetherNet. Other values are also supported but are currently not useful in LAN discovery
	// as it only allows connections over NetherNet. Therefore, the purposes or usage of this field is
	// currently unknown.
	TransportLayer uint8
	// ConnectionType indicates the connection type used alongside the transport layer.
	// In vanilla, this is typically 4 for using LAN as a signaling for NetherNet.
	// Other values are supported but are currently not useful in LAN discovery.
	ConnectionType uint8
}

// MarshalBinary ...
func (d *ServerData) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}

	_ = binary.Write(buf, binary.LittleEndian, version)
	writeBytes[uint8](buf, []byte(d.ServerName))
	writeBytes[uint8](buf, []byte(d.LevelName))
	_ = binary.Write(buf, binary.LittleEndian, d.GameType<<1)
	_ = binary.Write(buf, binary.LittleEndian, d.PlayerCount)
	_ = binary.Write(buf, binary.LittleEndian, d.MaxPlayerCount)
	_ = binary.Write(buf, binary.LittleEndian, d.EditorWorld)
	_ = binary.Write(buf, binary.LittleEndian, d.Hardcore)
	_ = binary.Write(buf, binary.LittleEndian, d.TransportLayer<<1)
	_ = binary.Write(buf, binary.LittleEndian, d.ConnectionType<<1)

	return buf.Bytes(), nil
}

// UnmarshalBinary ...
func (d *ServerData) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	var v uint8
	if err := binary.Read(buf, binary.LittleEndian, &v); err != nil {
		return fmt.Errorf("read version: %s", err)
	}
	if v != version {
		return fmt.Errorf("version mismatch: got %d, want %d", v, version)
	}
	serverName, err := readBytes[uint8](buf)
	if err != nil {
		return fmt.Errorf("read server name: %w", err)
	}
	d.ServerName = string(serverName)
	levelName, err := readBytes[uint8](buf)
	if err != nil {
		return fmt.Errorf("read level name: %w", err)
	}
	d.LevelName = string(levelName)
	var gameType uint8
	if err := binary.Read(buf, binary.LittleEndian, &gameType); err != nil {
		return fmt.Errorf("read game type: %w", err)
	}
	d.GameType = gameType >> 1
	if err := binary.Read(buf, binary.LittleEndian, &d.PlayerCount); err != nil {
		return fmt.Errorf("read player count: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.MaxPlayerCount); err != nil {
		return fmt.Errorf("read max player count: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.EditorWorld); err != nil {
		return fmt.Errorf("read editor world: %w", err)
	}
	if err := binary.Read(buf, binary.LittleEndian, &d.Hardcore); err != nil {
		return fmt.Errorf("read hardcore: %w", err)
	}
	var transportLayer uint8
	if err := binary.Read(buf, binary.LittleEndian, &transportLayer); err != nil {
		return fmt.Errorf("read transport layer: %w", err)
	}
	d.TransportLayer = transportLayer >> 1
	var connectionType uint8
	if err := binary.Read(buf, binary.LittleEndian, &connectionType); err != nil {
		return fmt.Errorf("read unknown: %w", err)
	}
	d.ConnectionType = connectionType >> 1
	if length := buf.Len(); length != 0 {
		return fmt.Errorf("unread %d bytes", length)
	}

	return nil
}

// version is the current version of ServerData as supported by the `discovery` package.
const version uint8 = 4
