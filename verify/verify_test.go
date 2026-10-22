package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"encoding/json"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
	keri "github.com/grapeid/keri-go"
)

type identity struct {
	t        *testing.T
	aid      string
	current  keri.Signer
	next     keri.Signer
	lastSAID string
	sn       int
	messages [][]byte
}

func newIdentity(t *testing.T) *identity {
	t.Helper()
	cur, _ := keri.GenerateSigner(true)
	nxt, _ := keri.GenerateSigner(true)
	pub, _ := cur.PublicKey()
	npub, _ := nxt.PublicKey()
	nd, err := keri.NextDigest(npub)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pub}, NextDigests: []string{nd}, Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, cur)
	if err != nil {
		t.Fatal(err)
	}
	return &identity{t: t, aid: parsed.Identifier, current: cur, next: nxt, lastSAID: parsed.SAID, messages: [][]byte{signed.Message}}
}

func (id *identity) rotate() {
	newNext, _ := keri.GenerateSigner(true)
	pub, _ := id.next.PublicKey()
	npub, _ := newNext.PublicKey()
	nd, _ := keri.NextDigest(npub)
	ev, err := keri.BuildRotation(keri.RotationInput{Prefix: id.aid, Keys: []string{pub}, PriorSAID: id.lastSAID, SN: id.sn + 1, NextDigests: []string{nd}})
	if err != nil {
		id.t.Fatal(err)
	}
	signed, err := keri.SignEvent(ev, id.next)
	if err != nil {
		id.t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	id.sn++
	id.lastSAID = parsed.SAID
	id.current, id.next = id.next, newNext
	id.messages = append(id.messages, signed.Message)
}

func (id *identity) kelB64() string {
	out, err := keri.ExportKEL(id.messages)
	if err != nil {
		id.t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(out)
}

func keyB64(t *testing.T, s keri.Signer) string {
	q, _ := s.PublicKey()
	raw, err := keri.MatterRaw(keri.CodeEd25519, q, ed25519.PublicKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestTheCurrentKeyOfAGenuineLogIsAccepted(t *testing.T) {
	id := newIdentity(t)
	r := KeyLog{}.Verify(id.aid, id.kelB64(), keyB64(t, id.current))
	if !r.Verified {
		t.Fatalf("refused a genuine log: %s", r.Reason)
	}
}

// Somebody else's log, however genuine, says nothing about this identifier.
func TestAnotherIdentitysLogIsRefused(t *testing.T) {
	mine, theirs := newIdentity(t), newIdentity(t)
	r := KeyLog{}.Verify(mine.aid, theirs.kelB64(), keyB64(t, theirs.current))
	if r.Verified || !strings.Contains(r.Reason, "not") {
		t.Fatalf("accepted %s's log for %s: %+v", theirs.aid, mine.aid, r)
	}
}

// A key of the caller's own, signed for and presented with a genuine log, is
// still not the identity's key.
func TestAKeyTheLogDoesNotNameIsRefused(t *testing.T) {
	id := newIdentity(t)
	stranger, _ := keri.GenerateSigner(true)
	if r := (KeyLog{}).Verify(id.aid, id.kelB64(), keyB64(t, stranger)); r.Verified {
		t.Fatal("accepted a key the log never named")
	}
}

// After a rotation only the new key speaks for the identity.
func TestAKeyRotatedAwayFromIsRefused(t *testing.T) {
	id := newIdentity(t)
	old := keyB64(t, id.current)
	id.rotate()
	if r := (KeyLog{}).Verify(id.aid, id.kelB64(), old); r.Verified {
		t.Fatal("accepted a key the identity has rotated away from")
	}
	if r := (KeyLog{}).Verify(id.aid, id.kelB64(), keyB64(t, id.current)); !r.Verified {
		t.Fatalf("refused the rotated-to key: %s", r.Reason)
	}
}

func TestATamperedLogIsRefused(t *testing.T) {
	id := newIdentity(t)
	raw, _ := base64.RawURLEncoding.DecodeString(id.kelB64())
	i := strings.Index(string(raw), `"k":["`) + 7
	raw[i] ^= 0x01
	if r := (KeyLog{}).Verify(id.aid, base64.RawURLEncoding.EncodeToString(raw), keyB64(t, id.current)); r.Verified {
		t.Fatal("accepted a log whose key was altered after signing")
	}
}

func TestNoLogAndAnOversizedLogAreRefused(t *testing.T) {
	id := newIdentity(t)
	if r := (KeyLog{}).Verify(id.aid, "", keyB64(t, id.current)); r.Verified {
		t.Fatal("accepted with no log")
	}
	huge := strings.Repeat("A", relayproto.MaxKELBytes*2)
	if r := (KeyLog{}).Verify(id.aid, huge, keyB64(t, id.current)); r.Verified || !strings.Contains(r.Reason, "larger") {
		t.Fatalf("an oversized log was not refused for its size: %+v", r)
	}
}

// One member of a group identity must not enrol as the group: a log naming two
// signing keys is refused, even when the key presented is one of them.
func TestAMemberOfAGroupCannotEnrolAsTheGroup(t *testing.T) {
	a, _ := keri.GenerateSigner(true)
	b, _ := keri.GenerateSigner(true)
	na, _ := keri.GenerateSigner(true)
	nb, _ := keri.GenerateSigner(true)
	pa, _ := a.PublicKey()
	pb, _ := b.PublicKey()
	npa, _ := na.PublicKey()
	npb, _ := nb.PublicKey()
	da, _ := keri.NextDigest(npa)
	db, _ := keri.NextDigest(npb)
	ev, err := keri.BuildInception(keri.InceptionInput{Keys: []string{pa, pb}, NextDigests: []string{da, db},
		Isith: json.RawMessage(`"2"`), Nsith: json.RawMessage(`"2"`), Derivation: "self-addressing"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := keri.ParseEvent(ev)
	signed, err := keri.SignEvent(ev, a, b)
	if err != nil {
		t.Fatal(err)
	}
	kel, _ := keri.ExportKEL([][]byte{signed.Message})
	if r := (KeyLog{}).Verify(parsed.Identifier, base64.RawURLEncoding.EncodeToString(kel), keyB64(t, a)); r.Verified {
		t.Fatal("one member of a two-key identity enrolled as the identity")
	}
}
