package resolver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	alterrors "alt/pkg/errors"
	"alt/pkg/profile"
	"alt/pkg/records"
	"alt/pkg/resolver"
)

type testBundle struct {
	prof         *profile.Profile
	authPub      ed25519.PublicKey
	authPriv     ed25519.PrivateKey
	ownerPub     ed25519.PublicKey
	ownerPriv    ed25519.PrivateKey
	manifestJSON []byte
	manifestCID  string
	now          time.Time
}

func buildTestBundle(t *testing.T, networkID, tld, domain string, gen, seq uint64, ownExp, tgtExp string) testBundle {
	t.Helper()
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signBundleWithKeys(t, authPub, authPriv, ownerPub, ownerPriv, networkID, tld, domain, gen, seq, ownExp, tgtExp)
}

func signBundleWithKeys(
	t *testing.T,
	authPub ed25519.PublicKey,
	authPriv ed25519.PrivateKey,
	ownerPub ed25519.PublicKey,
	ownerPriv ed25519.PrivateKey,
	networkID, tld, domain string,
	gen, seq uint64,
	ownExp, tgtExp string,
) testBundle {
	t.Helper()

	prof := &profile.Profile{
		Version:   1,
		NetworkID: networkID,
		TLD:       tld,
		RegistryKeys: []profile.RegistryKey{
			{ID: "registry-2026", PublicKey: records.FormatPublicKey(authPub)},
		},
		ReservedNames: []string{"register"},
	}
	if err := prof.Validate(); err != nil {
		t.Fatalf("profile validate: %v", err)
	}

	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      networkID,
		Domain:         domain,
		AccountID:      "acct_bootstrap",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     gen,
		IssuedAt:       "2026-11-12T00:00:00Z",
		ExpiresAt:      ownExp,
		IssuerKeyID:    "registry-2026",
	}
	if err := cert.Sign(authPriv); err != nil {
		t.Fatal(err)
	}

	target := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           networkID,
		Domain:              domain,
		OwnershipGeneration: gen,
		Sequence:            seq,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://register.example.org",
		IssuedAt:            "2026-11-12T00:00:00Z",
		ExpiresAt:           tgtExp,
	}
	if err := target.Sign(ownerPriv); err != nil {
		t.Fatal(err)
	}

	ownRaw, _ := json.Marshal(cert)
	tgtRaw, _ := json.Marshal(target)
	manifest := resolver.Manifest{
		Schema:    resolver.SchemaManifestV1,
		NetworkID: networkID,
		Generated: "2026-11-12T00:00:00Z",
		Records: map[string]resolver.ManifestEntry{
			domain: {
				Ownership: ownRaw,
				Target:    tgtRaw,
			},
		},
	}
	rawManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	cid := resolver.ComputeRawCIDv1(rawManifest)

	return testBundle{
		prof:         prof,
		authPub:      authPub,
		authPriv:     authPriv,
		ownerPub:     ownerPub,
		ownerPriv:    ownerPriv,
		manifestJSON: rawManifest,
		manifestCID:  cid,
		now:          time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC),
	}
}

func TestGatewayCIDVerificationAndUnknownNames(t *testing.T) {
	b := buildTestBundle(t, "alt-main-v1", "alt", "register.alt", 1, 1, "2030-01-01T00:00:00Z", "2027-01-01T00:00:00Z")

	var serveCorrupt bool
	var serveWrongContentType bool
	var serveServerError bool

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveServerError {
			http.Error(w, "gateway down", http.StatusBadGateway)
			return
		}
		if serveWrongContentType {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>gateway error page</html>"))
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ipld.raw")
		if serveCorrupt {
			_, _ = w.Write(append([]byte(nil), b.manifestJSON[:len(b.manifestJSON)-1]...))
			return
		}
		_, _ = w.Write(b.manifestJSON)
	}))
	defer gw.Close()

	src, err := resolver.NewGatewaySource(resolver.GatewayOptions{
		ManifestCID:     b.manifestCID,
		ExpectedNetwork: b.prof.NetworkID,
		Gateways:        []string{gw.URL},
		Timeout:         2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := resolver.New(b.prof, src)
	res.SetClock(func() time.Time { return b.now })

	// 1. Valid gateway resolution
	out, err := res.Resolve(context.Background(), "register.alt")
	if err != nil {
		t.Fatalf("Resolve register.alt failed: %v", err)
	}
	if out.Target.Target != "https://register.example.org" {
		t.Fatalf("unexpected target %q", out.Target.Target)
	}

	// 2. Unknown name in verified manifest returns NAME_NOT_FOUND
	_, err = res.Resolve(context.Background(), "unknown.alt")
	if !alterrors.IsCode(err, alterrors.CodeNameNotFound) {
		t.Fatalf("expected NAME_NOT_FOUND for unknown.alt, got: %v", err)
	}

	// 3. Gateway failure on uncached name returns RECORD_UNAVAILABLE
	resUncached := resolver.New(b.prof, src)
	resUncached.SetClock(func() time.Time { return b.now })
	serveServerError = true
	_, err = resUncached.Resolve(context.Background(), "register.alt")
	if !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected RECORD_UNAVAILABLE on HTTP 502, got: %v", err)
	}
	serveServerError = false

	// 4. Disallowed content type returns RECORD_UNAVAILABLE
	serveWrongContentType = true
	_, err = resUncached.Resolve(context.Background(), "register.alt")
	if !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected RECORD_UNAVAILABLE on text/html, got: %v", err)
	}
	serveWrongContentType = false

	// 5. Corrupt block failing CID hash check is rejected before decoding
	serveCorrupt = true
	_, err = resUncached.Resolve(context.Background(), "register.alt")
	if !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected RECORD_UNAVAILABLE on CID mismatch, got: %v", err)
	}
}

func TestSecurityRejectionsAndMonotonicCache(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	// 1. Distinct errors for expired ownership vs expired target
	bOwnExp := buildTestBundle(t, "alt-main-v1", "alt", "register.alt", 1, 1, "2026-11-12T01:00:00Z", "2027-01-01T00:00:00Z")
	resOwnExp := resolver.New(bOwnExp.prof, resolver.NewFixtureSource(bOwnExp.manifestJSON, bOwnExp.manifestCID, "alt-main-v1"))
	resOwnExp.SetClock(func() time.Time { return now })
	if _, err := resOwnExp.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeOwnershipExpired) {
		t.Fatalf("expected OWNERSHIP_EXPIRED, got: %v", err)
	}

	bTgtExp := buildTestBundle(t, "alt-main-v1", "alt", "register.alt", 1, 1, "2030-01-01T00:00:00Z", "2026-11-12T01:00:00Z")
	resTgtExp := resolver.New(bTgtExp.prof, resolver.NewFixtureSource(bTgtExp.manifestJSON, bTgtExp.manifestCID, "alt-main-v1"))
	resTgtExp.SetClock(func() time.Time { return now })
	if _, err := resTgtExp.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeTargetExpired) {
		t.Fatalf("expected TARGET_EXPIRED, got: %v", err)
	}

	// 2. Foreign networkId is rejected even when signed by the exact same authority key!
	bBase := buildTestBundle(t, "alt-main-v1", "alt", "register.alt", 2, 5, "2030-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
	bForeign := signBundleWithKeys(
		t, bBase.authPub, bBase.authPriv, bBase.ownerPub, bBase.ownerPriv,
		"foreign-alt-v1", "alt", "register.alt", 2, 5,
		"2030-01-01T00:00:00Z", "2027-01-01T00:00:00Z",
	)
	// Bypass manifest network check by passing empty expectedNetwork to FixtureSource so record-level check is exercised too
	resForeign := resolver.New(bBase.prof, resolver.NewFixtureSource(bForeign.manifestJSON, bForeign.manifestCID, ""))
	resForeign.SetClock(func() time.Time { return now })
	if _, err := resForeign.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected foreign networkId to be rejected with RECORD_UNAVAILABLE, got: %v", err)
	}

	// 3. A .mesh record cannot enter an .alt resolver
	bMesh := signBundleWithKeys(
		t, bBase.authPub, bBase.authPriv, bBase.ownerPub, bBase.ownerPriv,
		"alt-main-v1", "mesh", "register.mesh", 1, 1,
		"2030-01-01T00:00:00Z", "2027-01-01T00:00:00Z",
	)
	resAlt := resolver.New(bBase.prof, resolver.NewFixtureSource(bMesh.manifestJSON, bMesh.manifestCID, "alt-main-v1"))
	resAlt.SetClock(func() time.Time { return now })
	if _, err := resAlt.Resolve(context.Background(), "register.mesh"); !alterrors.IsCode(err, alterrors.CodeNameNotFound) {
		t.Fatalf("expected .mesh query in .alt resolver to fail with NAME_NOT_FOUND, got: %v", err)
	}

	// 4. Monotonic anti-rollback: lower sequence or lower generation never replaces cached state
	var activeBundle = bBase
	dynamicSource := resolverSourceFunc(func(ctx context.Context, domain string) ([]byte, []byte, error) {
		return resolver.NewFixtureSource(activeBundle.manifestJSON, activeBundle.manifestCID, "alt-main-v1").Resolve(ctx, domain)
	})
	resMono := resolver.New(bBase.prof, dynamicSource)
	resMono.SetClock(func() time.Time { return now })

	if _, err := resMono.Resolve(context.Background(), "register.alt"); err != nil {
		t.Fatalf("initial resolve (gen 2, seq 5) failed: %v", err)
	}

	// Rollback sequence 5 -> 4
	activeBundle = signBundleWithKeys(
		t, bBase.authPub, bBase.authPriv, bBase.ownerPub, bBase.ownerPriv,
		"alt-main-v1", "alt", "register.alt", 2, 4,
		"2030-01-01T00:00:00Z", "2027-01-01T00:00:00Z",
	)
	if _, err := resMono.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected sequence rollback to be rejected, got: %v", err)
	}

	// Rollback generation 2 -> 1 (even with higher sequence 99)
	activeBundle = signBundleWithKeys(
		t, bBase.authPub, bBase.authPriv, bBase.ownerPub, bBase.ownerPriv,
		"alt-main-v1", "alt", "register.alt", 1, 99,
		"2030-01-01T00:00:00Z", "2027-01-01T00:00:00Z",
	)
	if _, err := resMono.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected generation rollback to be rejected, got: %v", err)
	}

	// Malformed JSON rejected strictly
	malformedSrc := resolverSourceFunc(func(ctx context.Context, domain string) ([]byte, []byte, error) {
		return []byte(`{"schema":"alt.ownership.v1","unknownField":1}`), []byte(`{}`), nil
	})
	resMalformed := resolver.New(bBase.prof, malformedSrc)
	resMalformed.SetClock(func() time.Time { return now })
	if _, err := resMalformed.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected malformed/unknown-field JSON to be rejected, got: %v", err)
	}

	// 5. Mutating returned pointers or input pointers never mutates the verified cache
	resClone := resolver.New(bBase.prof, nil)
	resClone.SetClock(func() time.Time { return now })
	certIn, _ := records.DecodeOwnershipStrict(mustExtractOwnership(t, bBase.manifestJSON, "register.alt"))
	tgtIn, _ := records.DecodeTargetStrict(mustExtractTarget(t, bBase.manifestJSON, "register.alt"))
	if err := resClone.Ingest(certIn, tgtIn); err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	// Mutate caller input structs after Ingest
	certIn.Domain = "evil.alt"
	tgtIn.Target = "https://attacker.example.com"

	got1, err := resClone.Resolve(context.Background(), "register.alt")
	if err != nil || got1.Target.Target != "https://register.example.org" {
		t.Fatalf("expected cached target to be immune to input mutation, got %v %v", got1, err)
	}
	// Mutate returned resolution pointers
	got1.Target.Target = "https://mutated-after-resolve.example.com"
	got1.Ownership.Generation = 999

	got2, err := resClone.Resolve(context.Background(), "register.alt")
	if err != nil || got2.Target.Target != "https://register.example.org" || got2.Ownership.Generation != 2 {
		t.Fatalf("expected cached state to be immune to output mutation, got target=%q gen=%d err=%v",
			got2.Target.Target, got2.Ownership.Generation, err)
	}

	// 6. Invalid profile passed to NewChecked / New / NewWithConfig is never silently accepted
	invalidProf := &profile.Profile{
		Version:   99,
		NetworkID: "BAD_UPPERCASE",
		TLD:       "../bad",
	}
	if _, err := resolver.NewChecked(resolver.Config{Profile: invalidProf}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected NewChecked to reject invalid profile with CodeInvalidConfig, got: %v", err)
	}
	badRes := resolver.New(invalidProf, nil)
	if !alterrors.IsCode(badRes.InitError(), alterrors.CodeInvalidConfig) {
		t.Fatalf("expected badRes.InitError() to report CodeInvalidConfig, got: %v", badRes.InitError())
	}
	if _, err := badRes.Resolve(context.Background(), "register.alt"); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected Resolve on invalid-profile resolver to fail closed with CodeInvalidConfig, got: %v", err)
	}
	certValid, _ := records.DecodeOwnershipStrict(mustExtractOwnership(t, bBase.manifestJSON, "register.alt"))
	tgtValid, _ := records.DecodeTargetStrict(mustExtractTarget(t, bBase.manifestJSON, "register.alt"))
	if err := badRes.Ingest(certValid, tgtValid); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected Ingest on invalid-profile resolver to fail closed with CodeInvalidConfig, got: %v", err)
	}
}

func mustExtractOwnership(t *testing.T, rawManifest []byte, domain string) []byte {
	t.Helper()
	m, err := resolver.DecodeManifestStrict(rawManifest)
	if err != nil {
		t.Fatal(err)
	}
	return m.Records[domain].Ownership
}

func mustExtractTarget(t *testing.T, rawManifest []byte, domain string) []byte {
	t.Helper()
	m, err := resolver.DecodeManifestStrict(rawManifest)
	if err != nil {
		t.Fatal(err)
	}
	return m.Records[domain].Target
}

type resolverSourceFunc func(ctx context.Context, domain string) ([]byte, []byte, error)

func (f resolverSourceFunc) Resolve(ctx context.Context, domain string) ([]byte, []byte, error) {
	return f(ctx, domain)
}
