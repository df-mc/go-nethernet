package discovery

import (
	"bytes"
	"fmt"
)

// GameType represents the default game mode of a world.
const (
	GameTypeSurvival int32 = iota
	GameTypeCreative
	GameTypeAdventure
)

// ServerData defines the binary structure representing worlds in Minecraft: Bedrock Edition.
// It is encapsulated in [ResponsePacket.ApplicationData] and sent in response to [RequestPacket]
// broadcasted by clients on port 7551.
type ServerData struct {
	// ServerName is the name of the server. It is typically the player name of the owner
	// hosting the server and is displayed below the LevelName in the world card.
	ServerName string
	// Protocol is the protocol version used by the host of the server.
	Protocol int32
	// Version is the game version used by the host of the server.
	Version string
	// LevelName identifies the name of the world and appears at the top of ServerName in the world card.
	LevelName string
	// GameType is the default game mode of the world. Players receive this game mode when they
	// join. It remains unchanged during gameplay and may be updated the next time the world is hosted.
	GameType int32
	// PlayerCount is the amount of players currently connected to the world.
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
	// Nonce is a randomly generated, hex-encoded string produced by the host. Clients connecting
	// to this server must include this same value in the 'Nonce' field of the ClientData sent
	// in the connection request of the Login packet.
	Nonce string
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
	writeVarint32(buf, d.Protocol)
	writeString(buf, d.Version)
	writeString(buf, d.LevelName)
	writeVarint32(buf, d.PlayerCount)
	writeVarint32(buf, d.MaxPlayerCount)
	writeVarint32(buf, d.GameType)
	writeBool(buf, d.EditorWorld)
	writeBool(buf, d.Hardcore)
	writeBool(buf, d.AcceptsOnlineAuth)
	writeBool(buf, d.AcceptsSelfSignedAuth)
	writeString(buf, d.Nonce)
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
	d.Protocol, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read protocol: %w", err)
	}
	d.Version, err = readString(buf)
	if err != nil {
		return fmt.Errorf("read version: %w", err)
	}
	d.LevelName, err = readString(buf)
	if err != nil {
		return fmt.Errorf("read level name: %w", err)
	}
	d.PlayerCount, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read player count: %w", err)
	}
	d.MaxPlayerCount, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read max player count: %w", err)
	}
	d.GameType, err = readVarint32(buf)
	if err != nil {
		return fmt.Errorf("read game type: %w", err)
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
	d.Nonce, err = readString(buf)
	if err != nil {
		return fmt.Errorf("read nonce: %w", err)
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
const version uint8 = 7
