package nethernet

import (
	"cmp"
	"log/slog"
	"math/bits"
	"net/netip"
	"slices"

	"github.com/pion/webrtc/v4"
)

// fitSignal encodes desc as the data of signal. With a non-zero limit, it drops the bundled candidates
// least likely to reach the peer until the signal fits, keeping at least one, and logs a signal that
// still does not fit. Those are the candidates sharing the least of their subnet with any of remote.
func fitSignal(log *slog.Logger, desc *Description, remote []webrtc.ICECandidate, signal *Signal, limit int) error {
	if limit > 0 && len(desc.Candidates) > 1 {
		desc.Candidates = rankCandidates(desc.Candidates, remote)
	}
	for {
		data, err := desc.Encode()
		if err != nil {
			return err
		}
		signal.Data = string(data)
		length := len(signal.String())
		if limit == 0 || length <= limit {
			return nil
		}
		if len(desc.Candidates) <= 1 {
			log.Warn("signal exceeds the signaling length limit and may not arrive",
				slog.String("type", signal.Type),
				slog.Uint64("connectionID", signal.ConnectionID),
				slog.String("networkID", signal.NetworkID),
				slog.Int("length", length),
				slog.Int("limit", limit),
			)
			return nil
		}
		desc.Candidates = desc.Candidates[:len(desc.Candidates)-1]
	}
}

// rankCandidates returns local ordered by the largest share of its subnet each has in common with a
// remote candidate of the same family. Equal candidates keep their order, so with no comparable remote
// address the order is unchanged.
func rankCandidates(local, remote []webrtc.ICECandidate) []webrtc.ICECandidate {
	type ranked struct {
		candidate webrtc.ICECandidate
		shared    int
	}
	r := make([]ranked, len(local))
	for i, c := range local {
		r[i] = ranked{candidate: c, shared: sharedSubnet(c.Address, remote)}
	}
	slices.SortStableFunc(r, func(a, b ranked) int {
		return cmp.Compare(b.shared, a.shared)
	})
	out := make([]webrtc.ICECandidate, len(r))
	for i, c := range r {
		out[i] = c.candidate
	}
	return out
}

const (
	ipv4Subnet  = 24  // Prefix length of a typical IPv4 LAN.
	ipv6Subnet  = 64  // Prefix length of every IPv6 LAN.
	subnetScale = 192 // Least common multiple of both subnets, so scores stay integers.
)

// sharedSubnet scores how much of a typical subnet address shares with a remote candidate's address of
// the same family, from 0 to subnetScale for the same subnet, or -1 if none is comparable. An IPv4 /24
// and an IPv6 /64 match score the same, so a same-link IPv6 address outranks an IPv4 one on another subnet.
func sharedSubnet(address string, remote []webrtc.ICECandidate) int {
	local, err := netip.ParseAddr(address)
	if err != nil {
		return -1
	}
	local = local.Unmap()
	subnet := ipv6Subnet
	if local.Is4() {
		subnet = ipv4Subnet
	}
	best := -1
	for _, c := range remote {
		addr, err := netip.ParseAddr(c.Address)
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if addr.Is4() != local.Is4() {
			continue
		}
		shared := min(commonPrefixBits(local.AsSlice(), addr.AsSlice()), subnet)
		best = max(best, shared*subnetScale/subnet)
	}
	return best
}

// commonPrefixBits returns the number of leading bits a and b, of equal length, share.
func commonPrefixBits(a, b []byte) int {
	for i := range a {
		if x := a[i] ^ b[i]; x != 0 {
			return i*8 + bits.LeadingZeros8(x)
		}
	}
	return len(a) * 8
}
