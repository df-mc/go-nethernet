//go:build !windows

package discovery

import "syscall"

// setSocketBroadcast enables SO_BROADCAST on the socket, permitting sends to IPv4 broadcast
// addresses. The error is ignored: a socket that cannot carry broadcasts still serves IPv6.
func setSocketBroadcast(fd uintptr) {
	_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}
