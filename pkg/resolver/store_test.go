package resolver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	alterrors "alt/pkg/errors"
	"alt/pkg/records"
	"alt/pkg/resolver"
)

func TestStateStoreSurvivesRestartAndRejectsRollbackEvenAfterRecordExpiry(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "resolver-state.json")

	// Sign two generations:
	// - oldStale (gen=1, seq=1): valid until 2030 (long-lived stale record an attacker might replay)
	// - newerShortLived (gen=2, seq=5): expires at 2027-01-01
	oldStale := buildTestBundle(
		t,
		"alt-main-v1",
		"alt",
		"goker.alt",
		1,
		1,
		"2030-01-01T00:00:00Z",
		"2030-01-01T00:00:00Z",
	)
	newerShortLived := signBundleWithKeys(
		t,
		oldStale.authPub,
		oldStale.authPriv,
		oldStale.ownerPub,
		oldStale.ownerPriv,
		"alt-main-v1",
		"alt",
		"goker.alt",
		2,
		5,
		"2028-01-01T00:00:00Z",
		"2027-01-01T00:00:00Z",
	)
	staleSeq := signBundleWithKeys(
		t,
		oldStale.authPub,
		oldStale.authPriv,
		oldStale.ownerPub,
		oldStale.ownerPriv,
		"alt-main-v1",
		"alt",
		"goker.alt",
		2,
		4,
		"2028-01-01T00:00:00Z",
		"2028-01-01T00:00:00Z",
	)

	// Instance 1: ingest gen=2, seq=5 at 2026-12-01.
	store1, err := resolver.OpenStateStore(stateFile, "alt-main-v1")
	if err != nil {
		t.Fatalf("OpenStateStore(1): %v", err)
	}
	t1 := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	res1, err := resolver.NewChecked(resolver.Config{
		Profile:    oldStale.prof,
		Clock:      func() time.Time { return t1 },
		StateStore: store1,
	})
	if err != nil {
		t.Fatalf("NewChecked(1): %v", err)
	}

	var cert2 records.OwnershipCertificate
	var tgt2 records.TargetRecord
	var m2 resolver.Manifest
	_ = json.Unmarshal(newerShortLived.manifestJSON, &m2)
	_ = json.Unmarshal(m2.Records["goker.alt"].Ownership, &cert2)
	_ = json.Unmarshal(m2.Records["goker.alt"].Target, &tgt2)

	if err := res1.Ingest(&cert2, &tgt2); err != nil {
		t.Fatalf("Ingest(gen=2,seq=5): %v", err)
	}

	stInfo, err := os.Stat(stateFile)
	if err != nil {
		t.Fatalf("stat persisted state: %v", err)
	}
	if stInfo.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions on %s, got %04o", stateFile, stInfo.Mode().Perm())
	}

	// Simulate daemon restart AFTER newerShortLived target has expired (2027-06-01).
	// A malicious/stale gateway now serves oldStale (gen=1, seq=1) or staleSeq (gen=2, seq=4).
	t2 := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	store2, err := resolver.OpenStateStore(stateFile, "alt-main-v1")
	if err != nil {
		t.Fatalf("OpenStateStore(2): %v", err)
	}

	staleSrc := resolver.NewFixtureSource(oldStale.manifestJSON, oldStale.manifestCID, "alt-main-v1")
	res2, err := resolver.NewChecked(resolver.Config{
		Profile:    oldStale.prof,
		Source:     staleSrc,
		Clock:      func() time.Time { return t2 },
		StateStore: store2,
	})
	if err != nil {
		t.Fatalf("NewChecked(2): %v", err)
	}

	if _, err := res2.Resolve(context.Background(), "goker.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected generation rollback after restart to be rejected with RECORD_UNAVAILABLE, got %v", err)
	}

	// Also reject seq=4 under gen=2 across restart.
	staleSeqSrc := resolver.NewFixtureSource(staleSeq.manifestJSON, staleSeq.manifestCID, "alt-main-v1")
	res3, err := resolver.NewChecked(resolver.Config{
		Profile:    oldStale.prof,
		Source:     staleSeqSrc,
		Clock:      func() time.Time { return t2 },
		StateStore: store2,
	})
	if err != nil {
		t.Fatalf("NewChecked(3): %v", err)
	}
	if _, err := res3.Resolve(context.Background(), "goker.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected sequence rollback after restart to be rejected with RECORD_UNAVAILABLE, got %v", err)
	}

	// Advance to seq=6 under gen=2: succeeds and updates persisted watermark!
	freshSeq6 := signBundleWithKeys(
		t,
		oldStale.authPub,
		oldStale.authPriv,
		oldStale.ownerPub,
		oldStale.ownerPriv,
		"alt-main-v1",
		"alt",
		"goker.alt",
		2,
		6,
		"2028-01-01T00:00:00Z",
		"2028-01-01T00:00:00Z",
	)
	freshSrc := resolver.NewFixtureSource(freshSeq6.manifestJSON, freshSeq6.manifestCID, "alt-main-v1")
	res4, err := resolver.NewChecked(resolver.Config{
		Profile:    oldStale.prof,
		Source:     freshSrc,
		Clock:      func() time.Time { return t2 },
		StateStore: store2,
	})
	if err != nil {
		t.Fatal(err)
	}
	out, err := res4.Resolve(context.Background(), "goker.alt")
	if err != nil {
		t.Fatalf("expected seq=6 forward progression to succeed, got %v", err)
	}
	if out.Target.Sequence != 6 {
		t.Fatalf("expected sequence 6, got %d", out.Target.Sequence)
	}
}

func TestStateStoreRejectsNetworkMismatchTamperingAndInsecurePermissions(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "resolver-state.json")

	bundle := buildTestBundle(
		t,
		"alt-main-v1",
		"alt",
		"goker.alt",
		1,
		1,
		"2030-01-01T00:00:00Z",
		"2030-01-01T00:00:00Z",
	)

	store, err := resolver.OpenStateStore(stateFile, "alt-main-v1")
	if err != nil {
		t.Fatal(err)
	}
	res, err := resolver.NewChecked(resolver.Config{
		Profile:    bundle.prof,
		Clock:      func() time.Time { return bundle.now },
		StateStore: store,
	})
	if err != nil {
		t.Fatal(err)
	}

	var m resolver.Manifest
	var cert records.OwnershipCertificate
	var tgt records.TargetRecord
	_ = json.Unmarshal(bundle.manifestJSON, &m)
	_ = json.Unmarshal(m.Records["goker.alt"].Ownership, &cert)
	_ = json.Unmarshal(m.Records["goker.alt"].Target, &tgt)
	if err := res.Ingest(&cert, &tgt); err != nil {
		t.Fatal(err)
	}

	// 1. Cross-network reopen must fail.
	if _, err := resolver.OpenStateStore(stateFile, "other-net-v1"); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected cross-network OpenStateStore to fail with INVALID_CONFIG, got %v", err)
	}

	// 2. Group/world readable permissions must fail.
	if err := os.Chmod(stateFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.OpenStateStore(stateFile, "alt-main-v1"); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected 0644 state file to be rejected, got %v", err)
	}
	_ = os.Chmod(stateFile, 0o600)

	// 3. Tampered target URL inside persisted state must fail cryptographic re-verification on startup.
	otherBundle := buildTestBundle(
		t,
		"alt-main-v1",
		"alt",
		"goker.alt",
		1,
		1,
		"2030-01-01T00:00:00Z",
		"2030-01-01T00:00:00Z",
	)
	reloadedStore, err := resolver.OpenStateStore(stateFile, "alt-main-v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.NewChecked(resolver.Config{
		Profile:    otherBundle.prof, // different authority key -> signature mismatch!
		Clock:      func() time.Time { return bundle.now },
		StateStore: reloadedStore,
	}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected signature verification failure on tampered/mismatched authority key, got %v", err)
	}
}

func TestIPNSSourcePersistsSequenceAcrossRestartAndSupportsOfflineSnapshot(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "resolver-state.json")

	ipnsPub, ipnsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k51Root, err := resolver.EncodeK51Ed25519PublicKey(ipnsPub)
	if err != nil {
		t.Fatal(err)
	}

	bSeq1 := buildTestBundle(t, "alt-main-v1", "alt", "goker.alt", 1, 1, "2030-01-01T00:00:00Z", "2028-01-01T00:00:00Z")
	bSeq2 := signBundleWithKeys(t, bSeq1.authPub, bSeq1.authPriv, bSeq1.ownerPub, bSeq1.ownerPriv,
		"alt-main-v1", "alt", "goker.alt", 1, 2, "2030-01-01T00:00:00Z", "2028-01-01T00:00:00Z")

	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	eol := now.Add(24 * time.Hour)

	var mu sync.Mutex
	servedIPNS := buildSignedIPNSRecordV2(t, ipnsPriv, bSeq2.manifestCID, 10, eol, 5*time.Second)
	blocks := map[string][]byte{
		bSeq1.manifestCID: bSeq1.manifestJSON,
		bSeq2.manifestCID: bSeq2.manifestJSON,
	}
	gatewayOffline := false

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		offline := gatewayOffline
		ipnsRec := servedIPNS
		mu.Unlock()
		if offline {
			http.Error(w, "gateway unreachable", http.StatusBadGateway)
			return
		}
		if r.URL.Path == "/ipns/"+k51Root {
			w.Header().Set("Content-Type", "application/vnd.ipfs.ipns-record")
			_, _ = w.Write(ipnsRec)
			return
		}
		for cid, blk := range blocks {
			if r.URL.Path == "/ipfs/"+cid {
				w.Header().Set("Content-Type", "application/vnd.ipld.raw")
				_, _ = w.Write(blk)
				return
			}
		}
		http.NotFound(w, r)
	}))
	defer gw.Close()

	// Daemon run #1 resolves IPNS sequence=10 and persists it to disk.
	store1, err := resolver.OpenStateStore(stateFile, "alt-main-v1")
	if err != nil {
		t.Fatal(err)
	}
	src1, err := resolver.NewIPNSSource(resolver.IPNSOptions{
		IPNSRoot:        k51Root,
		ExpectedNetwork: "alt-main-v1",
		Gateways:        []string{gw.URL},
		Clock:           func() time.Time { return now },
		StateStore:      store1,
	})
	if err != nil {
		t.Fatal(err)
	}
	res1, err := resolver.NewChecked(resolver.Config{
		Profile:    bSeq1.prof,
		Source:     src1,
		Clock:      func() time.Time { return now },
		StateStore: store1,
	})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := res1.Resolve(context.Background(), "goker.alt")
	if err != nil || resolved.Target.Sequence != 2 {
		t.Fatalf("expected IPNS seq=10 / target seq=2 resolution, got %v (err=%v)", resolved, err)
	}

	// Daemon run #2 (fresh process simulation): gateway attempts to roll IPNS back from sequence 10 -> sequence 9!
	mu.Lock()
	servedIPNS = buildSignedIPNSRecordV2(t, ipnsPriv, bSeq1.manifestCID, 9, eol, 5*time.Second)
	mu.Unlock()

	store2, err := resolver.OpenStateStore(stateFile, "alt-main-v1")
	if err != nil {
		t.Fatal(err)
	}
	src2, err := resolver.NewIPNSSource(resolver.IPNSOptions{
		IPNSRoot:        k51Root,
		ExpectedNetwork: "alt-main-v1",
		Gateways:        []string{gw.URL},
		Clock:           func() time.Time { return now.Add(time.Minute) },
		StateStore:      store2,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Direct source query must reject the rolled-back IPNS sequence 9 (< persisted 10)!
	if _, _, err := src2.Resolve(context.Background(), "goker.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected restarted IPNSSource to reject rolled-back IPNS sequence 9, got %v", err)
	}

	// Daemon run #3: gateways go completely offline, but persisted verified manifest is still within EOL.
	mu.Lock()
	gatewayOffline = true
	mu.Unlock()

	src3, err := resolver.NewIPNSSource(resolver.IPNSOptions{
		IPNSRoot:        k51Root,
		ExpectedNetwork: "alt-main-v1",
		Gateways:        []string{gw.URL},
		Clock:           func() time.Time { return now.Add(2 * time.Minute) },
		StateStore:      store2,
	})
	if err != nil {
		t.Fatal(err)
	}
	res3, err := resolver.NewChecked(resolver.Config{
		Profile:    bSeq1.prof,
		Source:     src3,
		Clock:      func() time.Time { return now.Add(2 * time.Minute) },
		StateStore: store2,
	})
	if err != nil {
		t.Fatal(err)
	}
	offlineResolved, err := res3.Resolve(context.Background(), "goker.alt")
	if err != nil || !offlineResolved.FromCache || offlineResolved.Target.Sequence != 2 {
		t.Fatalf("expected offline survival via persisted Resolver cache, got %v (err=%v)", offlineResolved, err)
	}
}
