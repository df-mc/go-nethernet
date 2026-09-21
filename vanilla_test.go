package nethernet

import (
	"net"
	"strings"
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestGenerateVanillaICECredentialsLengths(t *testing.T) {
	ufrag, pwd := generateVanillaICECredentials()
	if len(ufrag) != vanillaUfragLen {
		t.Fatalf("ufrag len = %d, want %d", len(ufrag), vanillaUfragLen)
	}
	if len(pwd) != vanillaPwdLen {
		t.Fatalf("pwd len = %d, want %d", len(pwd), vanillaPwdLen)
	}
	for _, c := range ufrag + pwd {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", c) {
			t.Fatalf("non-alphanumeric credential char %q", c)
		}
	}
}

func TestKeepVanillaIPFiltersDocker(t *testing.T) {
	if keepVanillaIP(net.ParseIP("172.17.0.1")) {
		t.Fatal("172.17.0.1 (docker0) should be filtered")
	}
	if keepVanillaIP(net.ParseIP("127.0.0.1")) {
		t.Fatal("loopback should be filtered")
	}
	if keepVanillaIP(net.ParseIP("169.254.1.2")) {
		t.Fatal("link-local should be filtered")
	}
	if !keepVanillaIP(net.ParseIP("15.204.255.137")) {
		t.Fatal("public IPv4 should be kept")
	}
	if !keepVanillaIP(net.ParseIP("192.168.1.165")) {
		t.Fatal("site-local IPv4 should be kept")
	}
}

func TestFormatSDPCandidateMatchesVanilla(t *testing.T) {
	c := webrtc.ICECandidate{
		Foundation: "593530478",
		Priority:   2122260223,
		Address:    "10.2.0.2",
		Protocol:   webrtc.ICEProtocolUDP,
		Port:       63585,
		Typ:        webrtc.ICECandidateTypeHost,
	}
	first := formatSDPCandidate(1, c)
	if strings.Contains(first, "candidate:candidate:") || strings.HasPrefix(first, "candidate:") {
		t.Fatalf("SDP candidate must not include candidate: prefix, got %q", first)
	}
	if strings.Contains(first, "ufrag") {
		t.Fatalf("bundled SDP candidate must not include ufrag, got %q", first)
	}
	if !strings.Contains(first, "network-id 1") || !strings.Contains(first, "network-cost 50") {
		t.Fatalf("first candidate must carry network-id 1 and network-cost 50, got %q", first)
	}
	second := formatSDPCandidate(2, c)
	if strings.Contains(second, "network-cost") {
		t.Fatalf("second candidate must omit network-cost, got %q", second)
	}
	if !strings.Contains(second, "network-id 2") {
		t.Fatalf("second candidate must carry network-id 2, got %q", second)
	}
	wantPrefix := "593530478 1 udp 2122260223 10.2.0.2 63585 typ host generation 0 "
	if !strings.HasPrefix(first, wantPrefix) {
		t.Fatalf("candidate prefix = %q, want prefix %q", first, wantPrefix)
	}
}

func TestVanillaSettingEngineUsesShortCredentials(t *testing.T) {
	se := vanillaSettingEngine()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))
	g, err := api.NewICEGatherer(webrtc.ICEGatherOptions{})
	if err != nil {
		t.Fatalf("NewICEGatherer: %v", err)
	}
	defer g.Close()
	params, err := g.GetLocalParameters()
	if err != nil {
		t.Fatalf("GetLocalParameters: %v", err)
	}
	if len(params.UsernameFragment) != vanillaUfragLen {
		t.Fatalf("ufrag len = %d (%q), want %d", len(params.UsernameFragment), params.UsernameFragment, vanillaUfragLen)
	}
	if len(params.Password) != vanillaPwdLen {
		t.Fatalf("pwd len = %d, want %d", len(params.Password), vanillaPwdLen)
	}
}
