package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// Pinned bytes, because agreement is the whole point.
//
// The canonical form is the exact byte string that gets signed. If a client and
// a service disagree about it by even one character — a space, a key order, how
// a number is written — every signature fails, and the error a person sees is
// "signature invalid" with nothing pointing at why. It is a miserable failure to
// diagnose precisely because both sides look correct in isolation.
//
// So the output is pinned here rather than merely being tested for
// self-consistency. A refactor that changes these strings is not a refactor; it
// is a wire change that breaks every deployed signer at once, and it should
// have to be argued for rather than slipped through green tests.
//
// These vectors were captured on 2026-07-30 from the three implementations this
// module replaces, after confirming all three already agreed byte for byte.
var goldenVectors = []struct {
	name string
	in   map[string]interface{}
	want string
}{
	{
		name: "enrollment body, signature field removed",
		in: map[string]interface{}{
			"v": "IARELAY10JSON", "enrollment_aid": "EAbc",
			"oobi": "https://x.test", "signature": "this must not be signed over",
		},
		want: `{"enrollment_aid":"EAbc","oobi":"https://x.test","v":"IARELAY10JSON"}`,
	},
	{
		name: "keys sorted, including inside a nested object",
		in: map[string]interface{}{
			"z": 1, "a": 2,
			"m": map[string]interface{}{"b": 1, "a": 2},
		},
		want: `{"a":2,"m":{"a":2,"b":1},"z":1}`,
	},
	{
		name: "objects inside arrays are sorted too",
		in: map[string]interface{}{
			"list": []interface{}{map[string]interface{}{"z": 1, "a": 2}},
		},
		want: `{"list":[{"a":2,"z":1}]}`,
	},
	{
		name: "nesting goes all the way down",
		in: map[string]interface{}{
			"nested": map[string]interface{}{
				"deep": map[string]interface{}{"z": 1, "a": 2},
			},
		},
		want: `{"nested":{"deep":{"a":2,"z":1}}}`,
	},
	{
		// Go's encoding/json escapes <, > and & as \u003c, \u003e and \u0026 by
		// default. That is not what most JSON writers do, so anything
		// reimplementing this in another language will get it wrong unless it
		// is told — which is exactly why the real bytes are pinned here rather
		// than the ones that look right.
		name: "angle brackets and ampersands are escaped as Go escapes them",
		in:   map[string]interface{}{"esc": `a"b<c>d&e`},
		want: `{"esc":"a\"b\u003cc\u003ed\u0026e"}`,
	},
	{
		name: "an empty body is still an object",
		in:   map[string]interface{}{},
		want: `{}`,
	},
}

func TestCanonicalFormIsPinned(t *testing.T) {
	for _, tc := range goldenVectors {
		got, err := CanonicalBody(tc.in)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(got) != tc.want {
			t.Errorf("%s: the canonical form changed.\n  now:    %s\n  pinned: %s\n\n"+
				"This is a wire change, not a refactor: every already-deployed signer "+
				"and verifier disagrees with this build until they are all updated together.",
				tc.name, got, tc.want)
		}
	}
}

// The signature field must never be part of what is signed, or verification
// becomes circular and cannot succeed.
func TestTheSignatureFieldIsExcluded(t *testing.T) {
	withSig := map[string]interface{}{"a": 1, "signature": "0Bxxxx"}
	without := map[string]interface{}{"a": 1}

	a, _ := CanonicalBody(withSig)
	b, _ := CanonicalBody(without)
	if string(a) != string(b) {
		t.Errorf("the signature field leaked into the signed bytes:\n  %s\n  %s", a, b)
	}
}

// A round trip through an actual signature, so the pinned form is known to be
// usable and not merely stable.
func TestAPinnedFormVerifies(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := map[string]interface{}{"v": "IAMAILBOX10JSON", "aid": "EAbc"}

	canonical, err := CanonicalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canonical))

	if err := VerifyEd25519(base64.StdEncoding.EncodeToString(pub), sig, canonical); err != nil {
		t.Fatalf("a signature over the canonical form did not verify: %v", err)
	}
}

// Both spellings of base64 are accepted, because the agent side encodes
// signatures url-safe and unpadded while keys arrive standard-padded. A service
// that took only one would reject valid requests for a reason invisible from the
// error message.
func TestBothBase64SpellingsAreAccepted(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"a":1}`)
	raw := ed25519.Sign(priv, body)

	for name, encode := range map[string]func([]byte) string{
		"standard padded": base64.StdEncoding.EncodeToString,
		"standard raw":    base64.RawStdEncoding.EncodeToString,
		"url-safe padded": base64.URLEncoding.EncodeToString,
		"url-safe raw":    base64.RawURLEncoding.EncodeToString,
	} {
		if err := VerifyEd25519(encode(pub), encode(raw), body); err != nil {
			t.Errorf("%s encoding was rejected: %v", name, err)
		}
	}
}

// A wrong signature must fail, or none of the above means anything.
func TestAWrongSignatureIsRejected(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"a":1}`)

	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(otherPriv, body))
	if err := VerifyEd25519(base64.StdEncoding.EncodeToString(pub), sig, body); err == nil {
		t.Error("a signature by the wrong key verified")
	}
}
