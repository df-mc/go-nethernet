package discovery

import (
	"bytes"
	"fmt"
)

// GameType represents the default game mode of a world.
const (
	GameTypeSurvival       int32 = 0
	GameTypeCreative       int32 = 1
	GameTypeAdventure      int32 = 2
	GameTypeSurvivalViewer int32 = 3
	GameTypeCreativeViewer int32 = 4
	GameTypeDefault        int32 = 5
)

// TransportLayer indicates the transport protocol used by a server.
const (
	TransportLayerRakNet    int32 = 0
	TransportLayerNetherNet int32 = 2
	TransportLayerLocal     int32 = 4
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
	GameType int32
	// PlayerCount is the amount of players currently connected to the world. Worlds
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
	// AcceptsOnlineAuth indicates whether the server accepts online-authenticated (Xbox Live) players.
	AcceptsOnlineAuth bool
	// AcceptsSelfSignedAuth indicates whether the server accepts self-signed (LAN) authentication.
	AcceptsSelfSignedAuth bool
	// TransportLayer indicates the transport layer used by the server. In vanilla, this is typically
	// 2 for NetherNet. Other values are also supported but are currently not useful in LAN discovery
	// as it only allows connections over NetherNet. Therefore, the purposes or usage of this field is
	// currently unknown.
	TransportLayer int32
	// ConnectionType indicates the connection type used alongside the transport layer.
	// In vanilla, this is typically 4 for using LAN as a signaling for NetherNet.
	// Other values are supported but are currently not useful in LAN discovery.
	ConnectionType int32
}

// MarshalBinary ...
func (d *ServerData) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(version)
	writeString(buf, d.ServerName)
	writeString(buf, d.LevelName)
	writeVarint32(buf, d.GameType)
	writeInt32(buf, d.PlayerCount)
	writeInt32(buf, d.MaxPlayerCount)
	writeBool(buf, d.EditorWorld)
	writeBool(buf, d.Hardcore)
	writeBool(buf, d.AcceptsOnlineAuth)
	writeBool(buf, d.AcceptsSelfSignedAuth)
	writeVarint32(buf, d.TransportLayer)
	writeVarint32(buf, d.ConnectionType)

	return buf.Bytes(), nil
}

// UnmarshalBinary ...
func (d *ServerData) UnmarshalBinary(data []byte) error {
	buf := bytes.NewBuffer(data)

	v, err := buf.ReadByte()
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	if v != version {
		return fmt.Errorf("version mismatch: got %d, want %d", v, version)
	}
	d.ServerName, err = readString(buf)
	if err != nil {
		return fmt.Errorf("read server name: %w", err)
	}
	d.LevelName, err = readString(buf)
	if err != nil {
		return fmt.Errorf("read level name: %w", err)
	}
	d.GameType, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read game type: %w", err)
	}
	d.PlayerCount, err = readInt32(buf)
	if err != nil {
		return fmt.Errorf("read player count: %w", err)
	}
	d.MaxPlayerCount, err = readInt32(buf)
	if err != nil {
		return fmt.Errorf("read max player count: %w", err)
	}
	d.EditorWorld, err = readBool(buf)
	if err != nil {
		return fmt.Errorf("read editor world: %w", err)
	}
	d.Hardcore, err = readBool(buf)
	if err != nil {
		return fmt.Errorf("read hardcore: %w", err)
	}
	d.AcceptsOnlineAuth, err = readBool(buf)
	if err != nil {
		return fmt.Errorf("read accepts online auth: %w", err)
	}
	d.AcceptsSelfSignedAuth, err = readBool(buf)
	if err != nil {
		return fmt.Errorf("read accepts self-signed auth: %w", err)
	}
	d.TransportLayer, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read transport layer: %w", err)
	}
	d.ConnectionType, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read connection type: %w", err)
	}
	if length := buf.Len(); length != 0 {
		return fmt.Errorf("unread %d bytes", length)
	}

	return nil
}

// version is the current version of ServerData as supported by the `discovery` package.
const version uint8 = 5
