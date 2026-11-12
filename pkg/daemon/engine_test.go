package daemon_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"alt/pkg/config"
	"alt/pkg/daemon"
	"alt/pkg/records"
)

func TestEngineAtomicReloadAndRollbackProtection(t *testing.T) {
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	eng := daemon.NewEngine(authPub)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok-v1"))
	}))
	defer upstream.Close()

	validSite := config.SiteEntry{
		Routes: []config.RouteEntry{
			{Match: "/*", Upstream: upstream.URL},
		},
	}
	if err := eng.UpsertLocalSite("local.alt", validSite, t.TempDir()); err != nil {
		t.Fatalf("UpsertLocalSite failed: %v", err)
	}

	// Invalid reload must not break the active site configuration (§17)
	invalidSite := config.SiteEntry{
		Routes: []config.RouteEntry{},
	}
	if err := eng.UpsertLocalSite("local.alt", invalidSite, t.TempDir()); err == nil {
		t.Fatalf("expected error on invalid site reload")
	}

	req := httptest.NewRequest(http.MethodGet, "https://local.alt/", nil)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok-v1" {
		t.Fatalf("expected existing local site to remain intact after invalid reload, got %d %q", rec.Code, rec.Body.String())
	}

	// Verify monotonic sequence anti-rollback protection (§8, §17)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		Domain:         "goker.alt",
		AccountID:      "acct_1",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       "2026-11-03T00:00:00Z",
		ExpiresAt:      "2036-11-03T00:00:00Z",
		IssuerKeyID:    "reg-1",
	}
	_ = cert.Sign(authPriv)

	tSeq5 := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		Domain:              "goker.alt",
		OwnershipGeneration: 1,
		Sequence:            5,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://v5.example.com",
		IssuedAt:            "2026-11-03T00:00:00Z",
		ExpiresAt:           "2027-11-03T00:00:00Z",
	}
	_ = tSeq5.Sign(ownerPriv)

	if err := eng.IngestSignedRecords(cert, tSeq5, now); err != nil {
		t.Fatalf("IngestSignedRecords seq 5 failed: %v", err)
	}

	tSeq4 := *tSeq5
	tSeq4.Sequence = 4
	_ = tSeq4.Sign(ownerPriv)
	if err := eng.IngestSignedRecords(cert, &tSeq4, now); err == nil {
		t.Fatalf("expected rollback error when ingesting sequence 4 after sequence 5")
	}
}

