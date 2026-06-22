package nethernet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pion/webrtc/v4"
)

// Identity represents the authenticated identity used in a NetherNet peer connection.
type Identity struct {
	// PrivateKey is the private key corresponding to the 'cpk' claim contained
	// in [Identity.Token].
	//
	// It is used to sign the SDP fingerprint assertion carried in the 'a=identity'
	// attribute, binding the authenticated identity to the WebRTC peer connection.
	//
	// For server identities, this key is also used to self-sign [Identity.Token].
	PrivateKey *ecdsa.PrivateKey
	// Token is the JWT token for this identity.
	// For client identities, this token is issued by Minecraft's authorization service.
	// For server identities, this token is self-signed by the server using the [Identity.PrivateKey].
	// The JWT token must contain the corresponding public key for [Identity.PrivateKey] as the 'cpk' claim.
	Token string
	// Domain is the domain name that may be surfaced to players on first join when
	// connecting via an insecure (non-TLS) context.
	// For server identities, this can be "self", as observed on Bedrock Dedicated Server.
	Domain string
}

// sign signs the DTLS fingerprints included in the given local description using
// the [Identity.PrivateKey], and returns an identityData that can be embedded
// to the description.
func (i Identity) sign(desc *description) error {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: i.PrivateKey}, nil)
	if err != nil {
		return fmt.Errorf("create signer: %w", err)
	}
	payload := generateFingerprints(desc.dtls.Fingerprints)
	signature, err := signer.Sign(payload)
	if err != nil {
		return fmt.Errorf("sign DTLS fingerprints: %w", err)
	}
	detached, err := signature.DetachedCompactSerialize()
	if err != nil {
		return fmt.Errorf("generate DTLS fingerprints assertion: %w", err)
	}
	desc.identity = &identityData{
		Assertion: identityAssertion{
			Fingerprints: detached,
			Token:        i.Token,
		},
		IdentityProvider: identityProvider{
			Domain:   i.Domain,
			Protocol: "default",
		},
	}
	return nil
}

// claimPublicKey extracts and validates the public key from the 'cpk' claim in the JWT token.
// If selfSigned is true, it verifies that the token is self-signed with the corresponding private key.
// It also validates standard JWT claims such as expiration time.
func claimPublicKey(token string, selfSigned bool) (*ecdsa.PublicKey, error) {
	t, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{
		// Server identity tokens are self-signed using ES384
		jose.ES384,
		// Client identity tokens are issued by Minecraft's authorization service and are signed using RS256
		jose.RS256,
	})
	if err != nil {
		return nil, fmt.Errorf("parse JWT token: %w", err)
	}
	var claims tokenClaims
	if err := t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("extract JWT claims: %w", err)
	}
	if err := claims.Validate(jwt.Expected{Time: time.Now()}); err != nil {
		return nil, fmt.Errorf("validate JWT claims: %w", err)
	}
	if selfSigned {
		// Verify that server identity tokens are self-signed using the corresponding
		// private key for the cpk claim.
		if err := t.Claims(claims.PublicKey); err != nil {
			return nil, fmt.Errorf("verify JWT claims: %w", err)
		}
	}
	return claims.PublicKey, nil
}

// GenerateServerIdentity creates a new server Identity using the provided private key.
// The domain may be surfaced to players on first join when connecting via an insecure
// (non-TLS) context (though it is not functional in release versions somehow). The returned
// Identity contains a self-signed JWT token with a 1-minute expiration time and the public key
// embedded as the 'cpk' claim.
func GenerateServerIdentity(privateKey *ecdsa.PrivateKey, domain string) (*Identity, error) {
	encodedPublicKey, err := encodePublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: privateKey}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{
			// On Bedrock Dedicated Servers, just like the JWT token included in the
			// ServerToClientHandshake packet, this JWT token also includes the public
			// key in the 'x5u' claim.
			// Though it is not strictly required, we do this to match vanilla behavior.
			"x5u": encodedPublicKey,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	issuedAt := time.Now()
	token, err := jwt.Signed(signer).Claims(tokenClaims{
		Claims: jwt.Claims{
			Expiry:   jwt.NewNumericDate(issuedAt.Add(time.Minute)),
			IssuedAt: jwt.NewNumericDate(issuedAt),
		},
		PublicKey: &privateKey.PublicKey,
	}).Serialize()
	if err != nil {
		return nil, fmt.Errorf("generate JWT token: %w", err)
	}
	return &Identity{
		PrivateKey: privateKey,
		Token:      token,
		Domain:     domain,
	}, nil
}

// tokenClaims contains the essential JWT claims for both client and server identity tokens.
type tokenClaims struct {
	jwt.Claims
	PublicKey *ecdsa.PublicKey `json:"cpk"`
}

// MarshalJSON implements [json.Marshaler] for tokenClaims.
// It performs additional handling for encoding the cpk claim in base64.
func (c tokenClaims) MarshalJSON() ([]byte, error) {
	type Alias tokenClaims
	publicKey, err := encodePublicKey(c.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode cpk: %w", err)
	}
	return json.Marshal(struct {
		Alias
		PublicKey string `json:"cpk"`
	}{Alias: (Alias)(c), PublicKey: publicKey})
}

// UnmarshalJSON implements [json.Unmarshaler] for tokenClaims.
// It performs additional handling for decoding the cpk claim in base64.
func (c *tokenClaims) UnmarshalJSON(b []byte) (err error) {
	type Alias tokenClaims
	data := struct {
		*Alias
		PublicKey string `json:"cpk"`
	}{Alias: (*Alias)(c)}
	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}
	c.PublicKey, err = parsePublicKey(data.PublicKey)
	if err != nil {
		return fmt.Errorf("parse cpk: %w", err)
	}
	return nil
}

// Validate checks the validity of the JWT claims populated in this struct.
func (c tokenClaims) Validate(e jwt.Expected) error {
	if c.PublicKey == nil {
		return errors.New("nethernet: cpk is nil")
	}
	return c.Claims.Validate(e)
}

// generateFingerprints generates the canonical JSON payload covering DTLS fingerprints.
// The resulting bytes can be used as the payload for [jose.ParseDetached].
func generateFingerprints(fingerprints []webrtc.DTLSFingerprint) []byte {
	b := &bytes.Buffer{}
	b.WriteString(`{"fingerprint":[`)
	for i, fingerprint := range fingerprints {
		if i != 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"algorithm":`)
		b.WriteString(strconv.Quote(fingerprint.Algorithm))
		b.WriteString(`,"digest":`)
		b.WriteString(strconv.Quote(fingerprint.Value))
		b.WriteByte('}')
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

type (
	// identityData represents the complete identity assertion structure embedded in SDP
	// as the 'a=identity' attribute.
	identityData struct {
		// Assertion contains the JWT token and the detached JWS signature that is used
		// to bind the WebRTC peer connection to this identity.
		Assertion identityAssertion `json:"assertion"`
		// IdentityProvider contains the information about the issuer of the token included
		// in the assertion.
		IdentityProvider identityProvider `json:"idp"`
	}
	// identityAssertion contains the cryptographic components of an identity assertion.
	identityAssertion struct {
		// Fingerprints is the detached JWS signature which covers the DTLS fingerprints
		// attached to the remote description of the peer connection.
		Fingerprints string `json:"fingerprints"`
		// Token is the identity token issued for this identity assertion.
		// It corresponds to [Identity.Token].
		Token string `json:"token"`
	}
	// identityProvider contains information about the identity provider that issued
	// the token included in the identity assertion.
	identityProvider struct {
		// Domain is the domain name of the identity provider, may be displayed to players in first-use prompts.
		// For client connections, this locates the issuer which issued the multiplayer token, such as "https://authorization.franchise.minecraft-services.net".
		// For server connections, this is either "self" or the domain that issued the identity.
		Domain string `json:"domain"`
		// Protocol is always 'default' for NetherNet peer connections.
		Protocol string `json:"protocol"`
	}
)

// Valid reports whether the identityData is valid.
func (d identityData) Valid() bool {
	validJWS := func(s string) bool {
		return s != "" && strings.Count(s, ".") == 2
	}
	return validJWS(d.Assertion.Token) && validJWS(d.Assertion.Fingerprints) &&
		d.IdentityProvider.Protocol == "default" && d.IdentityProvider.Domain != ""
}

// verify verifies the fingerprints signature in the identity assertion using the provided public key.
// It reconstructs the canonical JSON payload from the description's DTLS fingerprints
// and validates the detached JWS signature.
// verify returns an error if the signature is invalid or malformed.
func (d identityData) verify(desc *description, publicKey *ecdsa.PublicKey) error {
	payload := generateFingerprints(desc.dtls.Fingerprints)
	signature, err := jose.ParseDetached(d.Assertion.Fingerprints, payload, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return fmt.Errorf("parse fingerprints assertion: %w", err)
	}
	if _, err := signature.Verify(publicKey); err != nil {
		return fmt.Errorf("verify fingerprints assertion: %w", err)
	}
	return nil
}

// MarshalJSON implements [json.Marshaler] for identityAssertion.
// It encodes the assertion to JSON then wraps the result as a JSON string.
func (a identityAssertion) MarshalJSON() ([]byte, error) {
	type Alias identityAssertion
	b, err := json.Marshal((Alias)(a))
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(b))
}

// UnmarshalJSON implements [json.Unmarshaler] for identityAssertion.
// It decodes the input as a JSON string then decodes the nested struct.
func (a *identityAssertion) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	type Alias identityAssertion
	return json.Unmarshal([]byte(s), (*Alias)(a))
}

// encodePublicKey encodes an ECDSA public key given by the user to a base64-encoded string.
func encodePublicKey(publicKey *ecdsa.PublicKey) (string, error) {
	if publicKey == nil {
		return "", errors.New("nethernet: public key is nil")
	}
	b, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal PKIX public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// parsePublicKey decodes a base64-encoded string as an ECDSA public key.
// It returns an error when the input is malformed or is not an ECDSA public key.
func parsePublicKey(s string) (*ecdsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	publicKey, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid key type: %T, expected *ecdsa.PublicKey", key)
	}
	return key, nil
}
