package sign

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// The bytes signed here are the published ones, read from the same vector file
// the Identity Agent's own tests hold its implementation to. Agreement is the
// whole point: a client and a service that differ by one character fail every
// signature with an error that points at nothing.
func TestThePublishedVectorsSignAndVerify(t *testing.T) {
	set, err := relayproto.SigningVectors()
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(set.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	for _, v := range set.Vectors {
		got, err := CanonicalBody(v.Fields)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(got) != v.Canonical {
			t.Fatalf("%s:\n got  %s\n want %s", v.Name, got, v.Canonical)
		}
		if err := VerifyEd25519(pub, v.Signature, got); err != nil {
			t.Fatalf("%s: the published signature does not verify: %v", v.Name, err)
		}
	}
	for _, r := range set.Refused {
		if _, err := CanonicalBody(r.Fields); err == nil {
			t.Fatalf("%s was signed; it must be refused", r.Name)
		}
	}
}

// A struct is signed by its JSON field names, the same as the map a client
// builds, so a service and a client agree whichever they use.
func TestAStructSignsLikeItsFields(t *testing.T) {
	type collect struct {
		V         string `json:"v"`
		AID       string `json:"aid"`
		Limit     string `json:"limit,omitempty"`
		Signature string `json:"signature"`
	}
	got, err := CanonicalBody(collect{V: "1", AID: "EAID", Limit: "50", Signature: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"aid":"EAID","limit":"50","v":"1"}`; string(got) != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestATamperedBodyFails(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	body := []byte(`{"aid":"EAID","v":"1"}`)
	sig := base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, body))
	key := base64.StdEncoding.EncodeToString(pub)
	if err := VerifyEd25519(key, sig, body); err != nil {
		t.Fatalf("an honest signature failed: %v", err)
	}
	if err := VerifyEd25519(key, sig, []byte(`{"aid":"EOTHER","v":"1"}`)); err == nil {
		t.Fatal("a signature verified over a different body")
	}
}
