# Security Policy

## Project Maturity Notice

ALT is currently an early open-source vertical slice (local HTTPS routing, constrained local CA, signed ownership/target verification, and content-addressed IPFS manifest resolution). It is **not** yet a production-hardened OS service, does not provide immediate real-time revocation, and carries no public SLA.

## Supported Versions

| Version / Branch | Supported |
| ---------------- | --------- |
| `main` (current slice) | Security fixes on best-effort basis |

## Security Invariants

Contributors and auditors should treat violations of any of the following invariants as security vulnerabilities:

1. **Constrained Local CA (`pkg/pki`):** Device-local Root CAs must carry X.509 `PermittedDNSDomains` constraints restricted strictly to the configured TLD and must refuse leaf issuance outside that namespace.
2. **Key Secrecy:** Private keys (CA keys, registry authority keys, owner keys) must be generated outside the repository with `0600` file permissions and `0700` directory permissions, and must never be committed or logged.
3. **Cross-Network Replay Prevention (`pkg/records`, `pkg/profile`):** Every ownership certificate and target record includes `networkId` both in its canonical JSON payload and in its Ed25519 domain-separation prefix (`alt.ownership.v1\x00<networkId>\x00` and `alt.target.v1\x00<networkId>\x00`). Records from one network must never validate on another.
4. **Untrusted Transport (`pkg/resolver`):** IPFS gateways and manifests are untrusted transport. Raw blocks must pass SHA-256 CIDv1 content-addressing verification, byte ceilings, content-type checks, strict JSON decoding, Ed25519 signature verification, validity-window checks, and monotonic generation/sequence anti-rollback rules before entering the verified cache.
5. **Loopback & SSRF Protection (`pkg/router`, `pkg/daemon`, `cmd/alt`):** Local listeners bind to explicit loopback IPs by default. Verified HTTPS origin dispatch refuses private, loopback, link-local, and unspecified IP ranges and dials verified IPs directly to prevent DNS rebinding.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security vulnerabilities.

Instead, report vulnerabilities privately via GitHub Private Vulnerability Reporting (Security Advisories) on the upstream repository, including:
- Affected package(s) and commit hash
- Minimal reproduction steps or proof-of-concept test
- Impact assessment (e.g., namespace escape, signature bypass, rollback, SSRF, path traversal)

Maintainers will acknowledge receipt and coordinate remediation before public disclosure.

