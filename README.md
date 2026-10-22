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

## Who imports it

The service-provider services that an [Identity Agent](https://github.com/LF-Decentralized-Trust-labs/identity-bot)
talks to over open protocols: `sp-mailbox` and `sp-url-relay` today. Any other
operator implementing those services in Go can import it too.

```sh
go get github.com/grapeid/sp-common@latest
```

```go
import (
    "github.com/grapeid/sp-common/sign"
    "github.com/grapeid/sp-common/oobi"
    "github.com/grapeid/sp-common/verify"
)
```

The signing form is the one set by the Identity Agent's ADR-049 (*One signing
form for every service-provider request*): Ed25519 over the request's fields as
a JSON object, every field a string of printable ASCII, keys sorted, no
whitespace, no HTML escaping, the `signature` field left out. `sign` does not
implement it; it calls `relayproto.CanonicalBody`, the Identity Agent's own
function. `verify` checks an enrolling key against the identity's signed key
event log, in process, with keri-go.

Run the tests with `go test ./...`. There is nothing to configure; it is a
library.

## Why these three, specifically

**`sign` fails silently when it drifts.** The canonical form is the exact byte
string that gets signed. If a client and a service disagree by one character — a
space, a key order, how a number is written — every signature fails, and what a
person sees is `signature invalid` with nothing pointing at why. It's a
miserable thing to diagnose because both sides look correct in isolation.

So there is one implementation, not a copy per service. `sign` calls
`relayproto.CanonicalBody`, and `sign/golden_test.go` holds it to the published
vectors (`relayproto.SigningVectors()`, the same file the Identity Agent's tests
use). **A change to those bytes is a wire change, not a refactor**, and it fails
in the Identity Agent's repository first.

Counts and lists travel as strings (`"limit": "50"`, `"message_ids": "m-1 m-2"`).
A number, a list or a nested object is refused rather than signed, because JSON
writers disagree about how to spell them.

**`oobi` fails silently when it drifts too, but in the other direction.** A rule
tightened in one service and not another is a gap nobody notices, because
nothing breaks — the service just stays reachable from somewhere it shouldn't
be.

**`verify` is where the security actually lives.** A signature proves the caller
holds the key they're presenting. It proves nothing about whose identifier it
is, because anybody can generate a key, sign with it, and name somebody else's
identifier. Only the identity's own key event log settles that, and asking it
correctly is subtle enough that it should be done once.

## How `verify` checks a key

The enrolling party sends its signed key event log as a CESR stream (base64url).
`verify.KeyLog` parses and validates it with keri-go, the engine the Identity
Agent itself runs, then checks that the log derives the identifier claimed and
names the presented key as its current one. Nothing is fetched from an address
the caller chose, and no other service is asked. The log is bounded
(`MaxKELBytes`, `MaxKELEvents`).

## History

These packages started as copies in `sp-url-relay` and `sp-mailbox`. Three
implementations of the signing form then disagreed about HTML escaping and
about numbers and lists. They are now one: the Identity Agent's
`relayproto.CanonicalBody`, which this module imports. Key logs used to be sent
to a separate KERI service for validation; they are now validated in process.

## Licence

Apache License 2.0 — see `LICENSE`. Contributions require a DCO sign-off; see
`CONTRIBUTING.md`. To report a vulnerability, see `SECURITY.md`.
