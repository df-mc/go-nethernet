//go:build windows

package discovery

import "syscall"

// setSocketBroadcast enables SO_BROADCAST on the socket, permitting sends to IPv4 broadcast
// addresses. The error is ignored: a socket that cannot carry broadcasts still serves IPv6.
func setSocketBroadcast(fd uintptr) {
	_ = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
}

// unreachableErrors are the send errors after which vanilla stops sending to a destination:
// WSAEHOSTUNREACH, WSAENETUNREACH, WSAEAFNOSUPPORT and WSAEFAULT.
var unreachableErrors = []error{syscall.Errno(10065), syscall.Errno(10051), syscall.Errno(10047), syscall.Errno(10014)}
