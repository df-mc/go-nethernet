package nethernet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pion/webrtc/v4"
)

func TestIdentitySignVerifyRoundTrip(t *testing.T) {
	privateKey := newIdentityTestKey(t)
	identity, err := GenerateServerIdentity(privateKey, "self")
	if err != nil {
		t.Fatalf("GenerateServerIdentity() error = %v", err)
	}
	publicKey, err := claimPublicKey(identity.Token, true)
	if err != nil {
		t.Fatalf("claimPublicKey() error = %v", err)
	}

	desc := newIdentityTestDescription()
	if err := identity.sign(desc); err != nil {
		t.Fatalf("sign() error = %v", err)
	}
	if err := desc.identity.verify(desc, publicKey); err != nil {
		t.Fatalf("verify() error = %v", err)
	}
}

func TestIdentityVerifyRejectsTamperedFingerprint(t *testing.T) {
	privateKey := newIdentityTestKey(t)
	identity, err := GenerateServerIdentity(privateKey, "self")
	if err != nil {
		t.Fatalf("GenerateServerIdentity() error = %v", err)
	}
	publicKey, err := claimPublicKey(identity.Token, true)
	if err != nil {
		t.Fatalf("claimPublicKey() error = %v", err)
	}

	desc := newIdentityTestDescription()
	if err := identity.sign(desc); err != nil {
		t.Fatalf("sign() error = %v", err)
	}
	desc.dtls.Fingerprints[0].Value = "FF:FF:FF:FF"
	if err := desc.identity.verify(desc, publicKey); err == nil {
		t.Fatal("verify() succeeded for tampered fingerprint")
	}
}

func TestClaimPublicKeyRejectsExpiredToken(t *testing.T) {
	privateKey := newIdentityTestKey(t)
	token, err := newIdentityTestToken(privateKey, time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatalf("newIdentityTestToken() error = %v", err)
	}
	if _, err := claimPublicKey(token, true); err == nil {
		t.Fatal("claimPublicKey() succeeded for expired token")
	}
}

func TestTokenClaimsMarshalRejectsNilPublicKey(t *testing.T) {
	_, err := json.Marshal(tokenClaims{})
	if err == nil || !strings.Contains(err.Error(), "public key is nil") {
		t.Fatalf("MarshalJSON() error = %v, want nil public key error", err)
	}
}

func TestClaimPublicKeyAcceptsJSONWebKey(t *testing.T) {
	privateKey := newIdentityTestKey(t)
	token, err := newIdentityTestTokenWithJSONWebKey(privateKey, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("newIdentityTestTokenWithJSONWebKey() error = %v", err)
	}
	publicKey, err := claimPublicKey(token, true)
	if err != nil {
		t.Fatalf("claimPublicKey() error = %v", err)
	}
	if !publicKey.Equal(&privateKey.PublicKey) {
		t.Fatal("claimPublicKey() returned a different public key")
	}
}

func TestParseClaimPublicKey(t *testing.T) {
	privateKey := newIdentityTestKey(t)
	encoded, err := encodePublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("encodePublicKey() error = %v", err)
	}
	base64Encoded, err := json.Marshal(encoded)
	if err != nil {
		t.Fatalf("marshal base64 cpk: %v", err)
	}
	webKeyEncoded, err := (&jose.JSONWebKey{Key: &privateKey.PublicKey}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal JSON web key cpk: %v", err)
	}

	for name, claim := range map[string]json.RawMessage{
		"base64":       base64Encoded,
		"json web key": webKeyEncoded,
	} {
		t.Run(name, func(t *testing.T) {
			publicKey, err := parseClaimPublicKey(claim)
			if err != nil {
				t.Fatalf("parseClaimPublicKey() error = %v", err)
			}
			if !publicKey.Equal(&privateKey.PublicKey) {
				t.Fatal("parseClaimPublicKey() returned a different public key")
			}
		})
	}

	t.Run("absent", func(t *testing.T) {
		for _, claim := range []json.RawMessage{nil, json.RawMessage("null")} {
			publicKey, err := parseClaimPublicKey(claim)
			if err != nil {
				t.Fatalf("parseClaimPublicKey(%s) error = %v", claim, err)
			}
			if publicKey != nil {
				t.Fatalf("parseClaimPublicKey(%s) = %v, want nil", claim, publicKey)
			}
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		if _, err := parseClaimPublicKey(json.RawMessage(`{"kty":"oct","k":"AAAA"}`)); err == nil {
			t.Fatal("parseClaimPublicKey() succeeded for a symmetric key")
		}
	})
}

func newIdentityTestDescription() *description {
	return &description{
		dtls: webrtc.DTLSParameters{
			Fingerprints: []webrtc.DTLSFingerprint{{
				Algorithm: "sha-256",
				Value:     "00:11:22:33:44:55:66:77",
			}},
		},
	}
}

func newIdentityTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	return privateKey
}

func newIdentityTestToken(privateKey *ecdsa.PrivateKey, expiresAt time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: privateKey}, nil)
	if err != nil {
		return "", err
	}
	issuedAt := expiresAt.Add(-time.Minute)
	return jwt.Signed(signer).Claims(tokenClaims{
		Claims: jwt.Claims{
			Expiry:   jwt.NewNumericDate(expiresAt),
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
		PublicKey: &privateKey.PublicKey,
	}).Serialize()
}

// newIdentityTestTokenWithJSONWebKey signs a token that encodes its cpk claim as a
// JSON Web Key, as Minecraft does since v1.26.40.
func newIdentityTestTokenWithJSONWebKey(privateKey *ecdsa.PrivateKey, expiresAt time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: privateKey}, nil)
	if err != nil {
		return "", err
	}
	issuedAt := expiresAt.Add(-time.Minute)
	return jwt.Signed(signer).Claims(struct {
		jwt.Claims
		PublicKey *jose.JSONWebKey `json:"cpk"`
	}{
		Claims: jwt.Claims{
			Expiry:   jwt.NewNumericDate(expiresAt),
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
		PublicKey: &jose.JSONWebKey{Key: &privateKey.PublicKey},
	}).Serialize()
}
