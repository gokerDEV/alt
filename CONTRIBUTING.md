# Contributing to ALT

Thank you for your interest in contributing to ALT!

## Scope and Language

- **Language:** All code, comments, commit messages, pull requests, issues, and documentation must be written in English.
- **Reusable Engine First:** ALT is built as a reusable private-namespace engine (`pkg/names`, `pkg/profile`, `pkg/dnsstub`, `pkg/pki`, `pkg/router`, `pkg/records`, `pkg/resolver`, `pkg/daemon`, `pkg/p2p/dcnet`). `.alt` is the default upstream network profile, not a hardcoded assumption.

## Development Workflow

1. **Prerequisites:** Go 1.25+ (or compatible toolchain in `go.mod`).
2. **Namespace Discipline:** Always validate and normalize domains/TLDs via `pkg/names` and network profiles via `pkg/profile`. Never introduce ad-hoc `.alt` string suffix checks.
3. **Security Hygiene:**
   - Never commit, log, or print private keys (`*.key`, CA private keys, Ed25519 seeds).
   - Bind listeners to explicit loopback addresses unless explicitly configured otherwise.
   - Enforce strict YAML/JSON decoding (reject unknown fields, duplicate keys, YAML anchors/aliases, and trailing bytes) and explicit byte/time bounds on all untrusted inputs.
   - Keep `alt run` unprivileged: do not modify `/etc`, the OS trust store, or `launchd` automatically during foreground runs or tests.

## Required Checks Before Submitting a PR

Every change must pass all four checks cleanly (enforced in `.github/workflows/ci.yml`):

```bash
test -z "$(gofmt -l .)"
go test ./...
go test -race ./...
go vet ./...
```

## Licensing

By submitting a contribution, you agree that:
- Code contributions are licensed under the **Apache License, Version 2.0** (see [LICENSE](LICENSE)).
- Documentation contributions are dual-licensed under **Apache-2.0** (see [LICENSE](LICENSE)) and **CC BY 4.0** (see [LICENSE-DOCS-CC-BY-4.0](LICENSE-DOCS-CC-BY-4.0) and [NOTICE](NOTICE)).

