# ALT: One-Day Delivery Plan

**Date:** November 12, 2026  
**Goal:** ship a demonstrable vertical slice today: local HTTPS routing plus IPFS-backed resolution of `register.alt`.  
**Project language:** English only.  
**Distribution:** open source; downstream operators can launch an independent namespace with their own TLD, authority key, registry, and IPFS/IPNS root.

## 1. Definition of done today

The day is successful when this path works on one development machine:

```text
local web app
   │ alt run register.alt --port 3000
   ▼
ALT local daemon
   ├── DNS response for the configured TLD
   ├── local CA and HTTPS ingress
   ├── local override routing
   └── IPFS resolver fallback
          ▼
signed register.alt record → verified target
```

Acceptance checks:

- `go test -race ./...` passes.
- `alt run register.alt --port 3000` starts a usable local route.
- `https://register.alt` reaches the app after the documented one-time trust/DNS setup.
- Removing the local override makes the resolver load the signed `register.alt` record from the configured IPFS source.
- Bad signatures, wrong networks/TLDs, expired records, and lower generations/sequences are rejected.
- The demo does not claim production-grade OS installation, global availability, or immediate revocation.

## 2. Non-goals today

- GitHub login, sponsorship, billing, quota, or public account recovery.
- Full IPNS propagation and multi-provider availability.
- WebRTC signaling, NAT traversal, or TURN.
- Automatic privileged macOS installation.
- Linux and Windows installers.
- A public SLA.

## 3. Work blocks

### A — English and open-source baseline

- [x] Make repository documentation English.
- [x] Keep comments and user-facing messages English.
- [x] Introduce a shared configurable namespace policy.
- [x] Select an OSI-approved license. Apache-2.0 is recommended, but the repository owner must explicitly choose it.
- [x] Add `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, and `SECURITY.md`.
- [x] Add a feature-status table that separates implemented, demo, beta, and planned behavior.

### B — Configurable namespace

The official build defaults to `.alt`. A downstream network must configure:

```text
TLD
network ID
registry authority keys
IPNS root or manifest CID
reserved names
resolver providers
branding
```

- [x] Add `pkg/names` as the single source of truth for TLD/domain validation.
- [x] Make DNS and the local CA namespace-aware while retaining `.alt` defaults.
- [x] Add TLD-aware config and ownership-record verification APIs.
- [x] Replace the temporary `ALT_TLD` switch with a versioned network profile.
- [x] Bind records to `networkId`; records must not be replayable between independent networks.
- [x] Include the network ID in every signature domain-separation prefix.

Proposed profile:

```yaml
version: 1
networkId: example-mesh-v1
tld: mesh
registryKeys:
  - id: registry-2026
    publicKey: ed25519:BASE64
resolver:
  ipnsRoot: k51...
  gateways:
    - https://example.invalid
reservedNames: [register]
```

### C — Local run vertical slice

- [x] Add `alt run <name> --port <port>` as a foreground demo command.
- [x] Build an in-memory site entry and register it in `daemon.Engine`.
- [x] Load or create the device CA in a user-scoped state directory.
- [x] Start HTTPS on an explicit high loopback port by default.
- [x] Add optional DNS serving for the selected TLD.
- [x] Handle SIGINT/SIGTERM and drain in-flight requests.
- [x] Add `--state-dir`, `--listen`, `--dns-listen`, and `--tld` flags.
- [x] Add an end-to-end smoke test.

Target command:

```bash
go run ./cmd/alt run register.alt \
  --port 3000 \
  --listen 127.0.0.1:8443 \
  --tld alt
```

Port 443 and OS resolver installation remain a separate privileged setup step.

### D — Minimal IPFS record source

Use a small adapter boundary; record verification must not depend on a gateway:

```go
type RecordSource interface {
    Resolve(ctx context.Context, domain string) (ownership []byte, target []byte, err error)
}
```

- [x] Define a manifest containing `networkId`, ownership, and target records.
- [x] Add `pkg/resolver` with source-independent verification and monotonic cache rules.
- [x] Add a fixture source for deterministic tests.
- [x] Add an HTTP IPFS gateway source that fetches an explicitly configured CID.
- [x] Verify content addressing before trusting decoded records.
- [x] Enforce byte limits, timeouts, content type, and strict JSON decoding.
- [x] Cache only fully verified records.
- [x] Test bad signatures, wrong networks, rollback, expiry, and malformed JSON.

A fixed manifest CID is acceptable today. Add IPNS only after the fixed-CID path is correct.

### E — `register.alt` bootstrap

- [x] Generate a development authority key outside the repository.
- [x] Sign ownership and target records for `register.alt`.
- [x] Publish the manifest to a local IPFS node or selected gateway.
- [x] Put only the public key and CID in the demo profile.
- [x] Resolve, verify, and route `register.alt`.
- [x] Document regeneration; never commit a private key.

Development keys must be visibly non-production. Production keys require a separate ceremony and secure storage.

## 4. Implementation order

1. Finish the foreground `run` command and smoke test.
2. Add the network profile loader and thread it through DNS, PKI, config, records, and resolver.
3. Implement the fixed-CID IPFS adapter.
4. Create signed test vectors and the `register.alt` fixture.
5. Connect resolver fallback to `daemon.Engine`.
6. Run unit, race, vet, and end-to-end checks.
7. Document exact demo commands and all limitations.

Do not start signaling, account management, or installer work before this path is green.

## 5. Security gates

- Private keys are never committed, printed, or stored with group/world permissions.
- Namespace checks use `pkg/names`; do not add suffix string checks.
- A network profile identifies the network, TLD, trust keys, and record root.
- IPFS data is untrusted until content addressing and signatures pass.
- HTTP reads have strict limits and timeouts.
- Listeners bind to loopback unless explicitly overridden.
- CA issuance is constrained to the configured namespace.
- `run` never modifies `/etc`, the trust store, or launchd.

## 6. Required tests

```bash
go test ./...
go test -race ./...
go vet ./...
```

- Local override wins over IPFS.
- Stopping it activates verified IPFS resolution.
- Unknown names return `NAME_NOT_FOUND`.
- Gateway failure returns `RECORD_UNAVAILABLE`.
- Expired ownership and targets have distinct errors.
- A `.mesh` record cannot enter an `.alt` engine.
- A foreign `networkId` is rejected even with a valid signature.
- Lower generations/sequences never replace cached state.
- HTTPS certificates are issued only for the configured namespace.

## 7. Open-source fork contract

```text
Reusable engine
  DNS + CA + router + records + resolver + optional P2P

Network profile
  TLD + network ID + authority keys + root pointer + reserved names

ALT distribution
  .alt profile + register.alt + official branding and services
```

Fork maintainers own namespace uniqueness, trust roots, registry policy, key security, abuse handling, IPFS availability, installers, and legal obligations. Independent private-TLD networks are not automatically globally unique or interoperable.

## 8. End-of-day handoff

Provide:

- exact local run commands;
- exact IPFS publish/resolve commands;
- public test keys/CIDs only;
- passing test output;
- known limitations;
- the next three issues ordered by risk.

