package records_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"alt/pkg/profile"
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
		NetworkID:      profile.DefaultNetworkID,
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
		NetworkID:           profile.DefaultNetworkID,
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
		NetworkID:           profile.DefaultNetworkID,
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

	// Cross-network replay detection: valid signature for foreign networkId is rejected
	foreignCert := *cert
	foreignCert.NetworkID = "rogue-alt-v1"
	if err := foreignCert.Sign(authPriv); err != nil {
		t.Fatal(err)
	}
	if err := foreignCert.VerifyForNetwork(authPub, now, profile.DefaultNetworkID, "alt"); !errors.Is(err, records.ErrInvalidNetworkID) {
		t.Fatalf("expected ErrInvalidNetworkID on foreign network replay, got: %v", err)
	}

	// Domain separation prefix binds networkId even if struct field were overwritten
	mutatedNetwork := foreignCert
	mutatedNetwork.NetworkID = profile.DefaultNetworkID
	if err := mutatedNetwork.VerifyForNetwork(authPub, now, profile.DefaultNetworkID, "alt"); !errors.Is(err, records.ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature when mutating networkId after signing, got: %v", err)
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

	// Validity window ordering: expiresAt <= issuedAt must be rejected even if expiresAt > now
	invertedWindow := *cert
	invertedWindow.IssuedAt = "2026-11-04T00:02:00Z"
	invertedWindow.ExpiresAt = "2026-11-04T00:01:00Z"
	_ = invertedWindow.Sign(authPriv)
	if err := invertedWindow.Verify(authPub, now); !errors.Is(err, records.ErrInvalidValidityWin) {
		t.Fatalf("expected ErrInvalidValidityWin when expiresAt <= issuedAt, got: %v", err)
	}

	// Strict net/url target and signaling validation (userinfo, fragment, query, missing host, invalid port)
	for _, badHTTPS := range []string{
		"https://",
		"https://user:pass@projem.vercel.app",
		"https://projem.vercel.app#frag",
		"https://projem.vercel.app?token=1",
		"https://projem.vercel.app:70000",
		"https://projem.vercel.app:",
	} {
		badRec := *httpsTarget
		badRec.Target = badHTTPS
		_ = badRec.Sign(ownerPriv)
		if err := badRec.Verify(cert, now); !errors.Is(err, records.ErrInvalidTargetMode) {
			t.Fatalf("expected ErrInvalidTargetMode for HTTPS target %q, got: %v", badHTTPS, err)
		}
	}

	for _, badWSS := range []string{
		"wss://",
		"wss://user@signal.example.org/v1",
		"wss://signal.example.org/v1#frag",
		"wss://signal.example.org/v1?room=1",
		"wss://signal.example.org:0/v1",
	} {
		badP2P := *p2pTarget
		badP2P.SignalingEndpoints = []string{badWSS}
		_ = badP2P.Sign(ownerPriv)
		if err := badP2P.Verify(cert, now); !errors.Is(err, records.ErrInvalidTargetMode) {
			t.Fatalf("expected ErrInvalidTargetMode for WSS endpoint %q, got: %v", badWSS, err)
		}
	}
}
