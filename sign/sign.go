package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// Proving a request came from the identifier it claims.
//
// Every service-provider request is signed over one form, set by the Identity
// Agent's ADR-049 and implemented once, in relayproto.CanonicalBody: the
// request's fields as a JSON object, every field a string of printable ASCII,
// keys sorted, no whitespace, no HTML escaping, the signature field left out.
// This package does not keep its own copy of that form. A second copy is how
// three implementations came to disagree about an ampersand.

// CanonicalBody returns the bytes a request is signed over. v is a struct or a
// map whose fields are all strings; a number, a list or a nested object is
// refused rather than signed in a spelling another implementation would not
// reproduce, so a request carries counts and lists as strings.
func CanonicalBody(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("a signed request is a JSON object: %w", err)
	}
	return relayproto.CanonicalBody(fields)
}

// VerifyEd25519 checks a signature over the canonical body.
func VerifyEd25519(publicKeyB64, signatureB64 string, body []byte) error {
	pubRaw, err := decode(publicKeyB64)
	if err != nil {
		return fmt.Errorf("public key is not valid base64")
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("public key is %d bytes, expected %d", len(pubRaw), ed25519.PublicKeySize)
	}
	sigRaw, err := decode(signatureB64)
	if err != nil {
		return fmt.Errorf("signature is not valid base64")
	}
	if len(sigRaw) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, expected %d", len(sigRaw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), body, sigRaw) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

// decode accepts both standard and url-safe base64, padded or not.
//
// Signatures are written base64url without padding (ADR-049). Keys arrive in
// whichever spelling a client's library produced, and refusing a valid key for
// its spelling gives an error nobody can act on.
func decode(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not base64")
}
