# sp-common

Shared building blocks for the service-provider services — the URL relay, the
mailbox, and whatever comes next.

Three packages, all here for the same reason: **they must behave identically
everywhere, and a copy per service is how that stops being true.**

| Package | |
|---|---|
| `sign` | the canonical byte form a request is signed over, and Ed25519 verification |
| `oobi` | validating a URL before fetching it, so a caller cannot aim this service at somewhere it shouldn't reach |
| `verify` | proving an enrolling key belongs to the identifier claiming it |

## Why these three, specifically

**`sign` fails silently when it drifts.** The canonical form is the exact byte
string that gets signed. If a client and a service disagree by one character — a
space, a key order, how a number is written — every signature fails, and what a
person sees is `signature invalid` with nothing pointing at why. It's a
miserable thing to diagnose because both sides look correct in isolation.

`sign/golden_test.go` pins the output bytes rather than merely testing for
self-consistency. **A change to those strings is a wire change, not a
refactor** — it breaks every deployed signer at once and should have to be
argued for rather than slipping through green tests.

One thing worth knowing if this is ever reimplemented in another language: Go's
`encoding/json` escapes `<`, `>` and `&` as `<`, `>` and `&` by
default. Most JSON writers don't. The golden vectors pin the real behaviour, not
the behaviour that looks right.

**`oobi` fails silently when it drifts too, but in the other direction.** A rule
tightened in one service and not another is a gap nobody notices, because
nothing breaks — the service just stays reachable from somewhere it shouldn't
be.

**`verify` is where the security actually lives.** A signature proves the caller
holds the key they're presenting. It proves nothing about whose identifier it
is, because anybody can generate a key, sign with it, and name somebody else's
identifier. Only the identity's own key event log settles that, and asking it
correctly is subtle enough that it should be done once.

## What is deliberately not here

**KERI validation itself.** `verify` fetches a key event log and asks a KERI
service whether it is genuine and belongs to the identifier claimed. Getting
that right means exact serialisation, exact hash inputs, and the same blanked
fields the reference implementation uses; reimplemented per service, that is
several chances to differ subtly and fail in ways nobody can debug.

## History

These packages started as copies in `sp-url-relay` and `sp-mailbox`. Before
merging them, all three implementations of the canonical form — including the
client's, in the Identity Agent itself — were compared byte for byte on nested
objects, arrays, escaping and number formatting. **They agreed.** So this is
consolidation of something already correct, not a repair.

The client's copy still lives in the Identity Agent and is not imported from
here: that repository's Go module has a bare name rather than a fetchable path,
so nothing outside it can import it. It remains a fourth copy, and the golden
vectors are the thing standing between it and silent drift.
