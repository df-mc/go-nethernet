package discovery

import "io"

// RequestPacket is sent by clients to discover servers on the same network using the
// broadcast address on port 7551. Servers listen on the same port and respond with a
// ResponsePacket containing basic information about their world.
type RequestPacket struct{}

// ID ...
func (*RequestPacket) ID() uint16 { return IDRequestPacket }

// Read ...
func (*RequestPacket) Read(io.Reader) error { return nil }

// Write ...
func (*RequestPacket) Write(io.Writer) {}
