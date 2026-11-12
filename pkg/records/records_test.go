package records_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"alt/pkg/records"
)

func TestOwnershipAndTargetVerification(t *testing.T) {
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubIdentityPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)

	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		Domain:         "goker.alt",
		AccountID:      "acct_01",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       "2026-11-03T00:00:00Z",
		ExpiresAt:      "2036-11-03T00:00:00Z",
		IssuerKeyID:    "registry-2026",
	}

	if err := cert.Sign(authPriv); err != nil {
		t.Fatalf("Sign ownership failed: %v", err)
	}

	if err := cert.Verify(authPub, now); err != nil {
		t.Fatalf("Verify ownership failed: %v", err)
	}

	// Verify HTTPS target record
	httpsTarget := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		Domain:              "goker.alt",
		OwnershipGeneration: 1,
		Sequence:            7,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://projem.vercel.app",
		IssuedAt:            "2026-11-03T00:00:00Z",
		ExpiresAt:           "2027-11-03T00:00:00Z",
	}
	if err := httpsTarget.Sign(ownerPriv); err != nil {
		t.Fatalf("Sign HTTPS target failed: %v", err)
	}
	if err := httpsTarget.Verify(cert, now); err != nil {
		t.Fatalf("Verify HTTPS target failed: %v", err)
	}

	// Verify P2P target record
	p2pTarget := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		Domain:              "goker.alt",
		OwnershipGeneration: 1,
		Sequence:            8,
		Mode:                records.TargetModeP2P,
		PublisherIdentity:   records.FormatPublicKey(pubIdentityPub),
		SignalingEndpoints:  []string{"wss://signal.example.org/v1"},
		IssuedAt:            "2026-11-03T00:00:00Z",
		ExpiresAt:           "2027-11-03T00:00:00Z",
	}
	if err := p2pTarget.Sign(ownerPriv); err != nil {
		t.Fatalf("Sign P2P target failed: %v", err)
	}
	if err := p2pTarget.Verify(cert, now); err != nil {
		t.Fatalf("Verify P2P target failed: %v", err)
	}

	// Tamper detection: change target URL after signing
	tampered := *httpsTarget
	tampered.Target = "https://attacker.example.com"
	if err := tampered.Verify(cert, now); !errors.Is(err, records.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature on tampered target, got: %v", err)
	}

	// Generation mismatch detection
	wrongGen := *httpsTarget
	wrongGen.OwnershipGeneration = 2
	_ = wrongGen.Sign(ownerPriv)
	if err := wrongGen.Verify(cert, now); !errors.Is(err, records.ErrGenerationMismatch) {
		t.Fatalf("expected ErrGenerationMismatch, got: %v", err)
	}

	// Expiry detection
	expiredTime := time.Date(2028, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := httpsTarget.Verify(cert, expiredTime); !errors.Is(err, records.ErrRecordExpired) {
		t.Fatalf("expected ErrRecordExpired, got: %v", err)
	}
}

