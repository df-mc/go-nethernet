package discovery

import (
	"net"
	"testing"
)

func TestListenAcceptsClientAddressForms(t *testing.T) {
	for _, tt := range []struct {
		name string
		addr string
	}{
		{name: "empty", addr: ""},
		{name: "portZero", addr: ":0"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l, err := (ListenConfig{}).Listen(tt.addr)
			if err != nil {
				t.Fatalf("Listen(%q): %v", tt.addr, err)
			}
			t.Cleanup(func() {
				if err := l.Close(); err != nil {
					t.Errorf("Close: %v", err)
				}
			})

			localAddr, ok := l.conn.LocalAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("local address = %T, want *net.UDPAddr", l.conn.LocalAddr())
			}
			if localAddr.Port == DefaultPort {
				t.Skipf("port-zero bind selected default port %d", DefaultPort)
			}
			if l.conf.BroadcastAddress == nil {
				t.Fatal("BroadcastAddress is nil")
			}
			if !l.conf.BroadcastAddress.IP.Equal(net.IPv4bcast) {
				t.Fatalf("BroadcastAddress.IP = %v, want %v", l.conf.BroadcastAddress.IP, net.IPv4bcast)
			}
			if l.conf.BroadcastAddress.Port != DefaultPort {
				t.Fatalf("BroadcastAddress.Port = %d, want %d", l.conf.BroadcastAddress.Port, DefaultPort)
			}
		})
	}
}
