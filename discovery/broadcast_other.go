//go:build !unix && !windows

package discovery

// setSocketBroadcast does nothing on platforms without SO_BROADCAST.
func setSocketBroadcast(uintptr) {}

// unreachableErrors is empty, as these platforms report no send errors to act on.
var unreachableErrors []error
