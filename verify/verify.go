package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"log"
	"strings"

	keri "github.com/grapeid/keri-go"
)

// Proving that a key belongs to the identifier enrolling with it.
//
// Enrolment arrives with an identifier and a public key, and a signature made
// by that key over the request. That proves the caller holds the key. It proves
// nothing about whose identifier it is: anybody can make a key, sign with it,
// and name somebody else's identifier.
//
// The binding lives in the identifier's own key event log. A self-addressing
// identifier is the digest of its inception event, so a log either derives
// this identifier or it does not, and the key in force after its last event is
// the only one entitled to speak for it.
//
// So the enrolling party sends its signed key event log, and this package
// checks it in this process with keri-go: the same engine the Identity Agent
// runs, so the check cannot drift from the one that made the log. Nothing is
// fetched from an address the caller chose, and no other service is asked.
//
// How bad it is to skip this depends on what enrolling grants, and that differs
// by service. Each service says which in its own README.

// Result is what verification concluded.
type Result struct {
	// Verified is true only when the log verified, derives this identifier,
	// and names the presented key as its current one.
	Verified bool
	// CurrentKey is the current signing key, qb64. Empty unless verified.
	CurrentKey string
	// Reason explains a refusal in terms somebody can act on.
	Reason string
}

// Verifier binds an enrolling key to its identifier.
type Verifier interface {
	// Verify reports whether publicKeyB64 is aid's current signing key,
	// according to the signed key event log kelB64 (a CESR stream, base64url).
	Verify(aid, kelB64, publicKeyB64 string) Result
	// Enabled reports whether this verifier checks anything, so a service can
	// say so at start-up rather than appearing to be strict.
	Enabled() bool
}

// Limits on a presented log. It arrives in a request, so its size is the
// caller's choice until it is bounded.
const (
	MaxKELBytes  = 64 << 10
	MaxKELEvents = 256
)

// KeyLog verifies with keri-go, in process.
type KeyLog struct{}

func (KeyLog) Enabled() bool { return true }

func (KeyLog) Verify(aid, kelB64, publicKeyB64 string) Result {
	if strings.TrimSpace(kelB64) == "" {
		return Result{Reason: "a signed key event log is required: without one there is nothing to check this key against"}
	}
	if len(kelB64) > MaxKELBytes*4/3+4 {
		return Result{Reason: fmt.Sprintf("the key event log is larger than %d bytes", MaxKELBytes)}
	}
	stream, err := decode(kelB64)
	if err != nil {
		return Result{Reason: "the key event log is not base64"}
	}
	messages, err := keri.ParseKELStream(stream)
	if err != nil {
		return Result{Reason: "the key event log is not readable: " + err.Error()}
	}
	if len(messages) > MaxKELEvents {
		return Result{Reason: fmt.Sprintf("the key event log has %d events; the limit is %d", len(messages), MaxKELEvents)}
	}
	state, err := keri.ValidateSignedKEL(messages)
	if err != nil {
		return Result{Reason: "the key event log does not verify: " + err.Error()}
	}
	if state.Identifier != aid {
		// Worth naming precisely: the honest version of this mistake, sending
		// the wrong log, looks identical to the dishonest one.
		return Result{Reason: fmt.Sprintf("that key event log is %s's, not %s's", state.Identifier, aid)}
	}
	presented, err := decode(publicKeyB64)
	if err != nil || len(presented) != ed25519.PublicKeySize {
		return Result{Reason: "the public key is not a base64 Ed25519 key"}
	}
	for _, k := range state.Keys {
		raw, err := keri.MatterRaw(keri.CodeEd25519, k, ed25519.PublicKeySize)
		if err != nil {
			continue
		}
		if ed25519.PublicKey(raw).Equal(ed25519.PublicKey(presented)) {
			return Result{Verified: true, CurrentKey: k}
		}
	}
	// The key is real and the identifier is real; they are not each other's.
	// Most often a key the identity has since rotated away from.
	return Result{Reason: "the key presented is not this identity's current signing key"}
}

// Unverified accepts every enrolment without checking.
//
// For development and tests only, and loud about it: a service running with
// this is open to identifier squatting and says so on every enrolment.
type Unverified struct{}

func (Unverified) Enabled() bool { return false }

func (Unverified) Verify(aid, _, _ string) Result {
	log.Printf("[verify] WARNING: enrolling %q without checking the key belongs to it; "+
		"this operator is open to identifier squatting", aid)
	return Result{Verified: false, Reason: "verification is disabled on this operator"}
}

func decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return nil, fmt.Errorf("not base64")
}
