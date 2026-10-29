package nethernet

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

// VerifyOfferIdentity accepts only offers whose fingerprints the token's key signed.
func TestVerifyOfferIdentity(t *testing.T) {
	privateKey := newIdentityTestKey(t)
	token, err := newIdentityTestToken(privateKey, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	offer := func(t *testing.T, mutate func(*description)) string {
		t.Helper()
		desc := newIdentityTestDescription()
		desc.ice = webrtc.ICEParameters{UsernameFragment: "ufrag", Password: "password"}
		desc.dtls.Role = webrtc.DTLSRoleClient
		desc.sctp.MaxMessageSize = 262144
		if err := (Identity{PrivateKey: privateKey, Token: token, Domain: "test"}).sign(desc); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(desc)
		}
		b, err := desc.encode()
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	fromClaim := func(context.Context, string) (*ecdsa.PublicKey, error) { return nil, nil }

	got, err := VerifyOfferIdentity(t.Context(), offer(t, nil), fromClaim)
	if err != nil || got != token {
		t.Fatalf("VerifyOfferIdentity() = %q, %v; want the offer's token", got, err)
	}

	tampered := offer(t, func(d *description) { d.dtls.Fingerprints[0].Value = "FF:FF:FF:FF" })
	if _, err := VerifyOfferIdentity(t.Context(), tampered, fromClaim); err == nil {
		t.Fatal("VerifyOfferIdentity() accepted an offer whose fingerprints the token's key did not sign")
	}

	rejected := errors.New("token not issued by the authorization service")
	if _, err := VerifyOfferIdentity(t.Context(), offer(t, nil), func(context.Context, string) (*ecdsa.PublicKey, error) { return nil, rejected }); !errors.Is(err, rejected) {
		t.Fatalf("VerifyOfferIdentity() error = %v, want the token verifier's error", err)
	}

	anonymous := offer(t, func(d *description) { d.identity = nil })
	if _, err := VerifyOfferIdentity(t.Context(), anonymous, fromClaim); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("VerifyOfferIdentity() error = %v, want ErrNoIdentity", err)
	}
	if strings.Contains(anonymous, "a=identity") {
		t.Fatal("anonymous test offer still carries an identity")
	}
}
