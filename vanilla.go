package nethernet

import (
	"crypto/rand"
	"net"
	"strconv"
	"strings"

	"github.com/pion/webrtc/v4"
)

const (
	// vanillaUfragLen matches the vanilla Bedrock client (e.g. "iqQH").
	vanillaUfragLen = 4
	// vanillaPwdLen matches the vanilla Bedrock client (e.g. 22-char pwd).
	vanillaPwdLen = 22
)

var vanillaCredentialAlphabet = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

// generateVanillaICECredentials returns short ICE credentials matching the
// vanilla Bedrock client: a 4-character ufrag and a 22-character password.
// Pion defaults to longer values (16/32) which stand out in SDP captures.
func generateVanillaICECredentials() (ufrag, pwd string) {
	return randomVanillaString(vanillaUfragLen), randomVanillaString(vanillaPwdLen)
}

func randomVanillaString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; fall back to zeros on error to
		// avoid panicking in the handshake path.
		for i := range b {
			b[i] = vanillaCredentialAlphabet[0]
		}
		return string(b)
	}
	for i := range b {
		b[i] = vanillaCredentialAlphabet[int(b[i])%len(vanillaCredentialAlphabet)]
	}
	return string(b)
}

// vanillaSettingEngine returns a SettingEngine that mimics the vanilla
// Bedrock client during ICE gathering:
//   - short ICE ufrag/pwd (4/22) instead of Pion's longer defaults,
//   - container/virtual interfaces (docker0, veth*, br-*) excluded so the
//     Docker bridge (e.g. 172.17.0.1) never leaks into SDP candidates,
//   - loopback, link-local and multicast addresses excluded.
func vanillaSettingEngine() webrtc.SettingEngine {
	var se webrtc.SettingEngine
	ufrag, pwd := generateVanillaICECredentials()
	se.SetICECredentials(ufrag, pwd)
	se.SetInterfaceFilter(func(name string) (keep bool) {
		lower := strings.ToLower(name)
		if lower == "lo" || strings.HasPrefix(lower, "docker") || strings.HasPrefix(lower, "veth") || strings.HasPrefix(lower, "br-") {
			return false
		}
		return true
	})
	se.SetIPFilter(keepVanillaIP)
	return se
}

// defaultVanillaAPI creates the default WebRTC API used when Dialer.API or
// ListenConfig.API is nil. It matches the vanilla client as described in
// vanillaSettingEngine.
func defaultVanillaAPI() *webrtc.API {
	return webrtc.NewAPI(webrtc.WithSettingEngine(vanillaSettingEngine()))
}

// keepVanillaIP reports whether ip should be advertised as a host candidate.
// It filters loopback, link-local, multicast and the well-known Docker
// bridge networks while keeping public and site-local addresses (the proxy
// host's public IP is still advertised as a host candidate, which is
// unavoidable and technically correct for a host with a public interface).
func keepVanillaIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Filter Docker default bridges explicitly. These are private subnets
	// that never appear in vanilla client SDPs and immediately identify a
	// containerised proxy (e.g. 172.17.0.1 from docker0).
	if ip4 := ip.To4(); ip4 != nil {
		if ip4[0] == 172 && ip4[1] == 17 && len(ip4) == 4 {
			// 172.17.0.0/16 (docker0 default)
			return false
		}
		if ip4[0] == 172 && ip4[1] == 18 {
			// 172.18.0.0/16 (common second docker network)
			return false
		}
	}
	return true
}

// filterVanillaCandidates drops candidates that would never appear in a
// vanilla client SDP (Docker bridge, loopback, link-local, unspecified).
// It is applied as a safety net in encode() even though gathering already
// filters via vanillaSettingEngine.
func filterVanillaCandidates(candidates []webrtc.ICECandidate) []webrtc.ICECandidate {
	out := candidates[:0]
	for _, c := range candidates {
		ip := net.ParseIP(c.Address)
		if ip == nil || !keepVanillaIP(ip) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// formatSDPCandidate formats a candidate for embedding in an SDP offer or
// answer, matching the vanilla Bedrock client byte-for-byte:
//
//	a=candidate:<foundation> 1 udp <priority> <ip> <port> typ host generation 0 network-id <id>[ network-cost 50]
//
// Differences from formatICECandidate (used for trickle CANDIDATEADD):
//   - no "candidate:" prefix: pion/sdp already emits "a=candidate:" from the
//     attribute key, so including it would produce "candidate:candidate:",
//   - no inline "ufrag": vanilla bundled candidates carry no ufrag,
//   - network-id is 1-based (vanilla uses 1,2; Pion code used 0,1,2),
//   - only the first candidate carries "network-cost 50", matching observed
//     vanilla offers/answers where the first network has cost 50 and the
//     rest omit it.
func formatSDPCandidate(id int, candidate webrtc.ICECandidate) string {
	// id is 1-based. The caller passes i+1.
	b := &strings.Builder{}
	// NOTE: no "candidate:" prefix here; sdp.Attribute marshals as
	// "a=candidate:<value>".
	b.WriteString(candidate.Foundation)
	b.WriteByte(' ')
	b.WriteByte('1')
	b.WriteByte(' ')
	b.WriteString(candidate.Protocol.String())
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(uint64(candidate.Priority), 10))
	b.WriteByte(' ')
	b.WriteString(candidate.Address)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatUint(uint64(candidate.Port), 10))
	b.WriteByte(' ')
	b.WriteString("typ")
	b.WriteByte(' ')
	b.WriteString(candidate.Typ.String())
	b.WriteByte(' ')
	if candidate.Typ == webrtc.ICECandidateTypeRelay || candidate.Typ == webrtc.ICECandidateTypeSrflx {
		b.WriteString("raddr")
		b.WriteByte(' ')
		b.WriteString(candidate.RelatedAddress)
		b.WriteByte(' ')
		b.WriteString("rport")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(uint64(candidate.RelatedPort), 10))
		b.WriteByte(' ')
	}
	b.WriteString("generation 0 network-id ")
	b.WriteString(strconv.Itoa(id))
	if id == 1 {
		b.WriteString(" network-cost 50")
	}
	return b.String()
}
