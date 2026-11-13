package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alt/pkg/pki"
)

func TestDeviceCAAndLeafVerification(t *testing.T) {
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA failed: %v", err)
	}

	// Reloading existing CA succeeds
	reloaded, err := pki.LoadOrCreateCA(dir)
	if err != nil || reloaded.TLD() != "alt" {
		t.Fatalf("reload CA failed: %v", err)
	}

	// Verify that non-.alt domains are rejected
	if _, err := ca.IssueLeaf("example.com"); !errors.Is(err, pki.ErrUnsupportedDomain) {
		t.Fatalf("expected ErrUnsupportedDomain for example.com, got: %v", err)
	}

	tlsCert, err := ca.GetCertificate(&tls.ClientHelloInfo{ServerName: "goker.alt"})
	if err != nil {
		t.Fatalf("GetCertificate for goker.alt failed: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate())

	_, err = tlsCert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "goker.alt",
		Roots:   roots,
	})
	if err != nil {
		t.Fatalf("leaf certificate verification against device CA failed: %v", err)
	}
}

func TestParseCARejectsMismatchedUnconstrainedExpiredAndInsecureCA(t *testing.T) {
	ca1, key1, err := pki.GenerateCAForTLD("alt")
	if err != nil {
		t.Fatal(err)
	}
	_, key2, err := pki.GenerateCAForTLD("alt")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Mismatched cert and private key
	if _, err := pki.ParseCA(ca1.CertPEM(), key2); !errors.Is(err, pki.ErrInvalidCAKey) {
		t.Fatalf("expected ErrInvalidCAKey on mismatched keypair, got: %v", err)
	}

	// 2. Expired CA
	future := time.Now().UTC().AddDate(20, 0, 0)
	if _, err := pki.ParseCAAt(ca1.CertPEM(), key1, future); !errors.Is(err, pki.ErrInvalidCACert) {
		t.Fatalf("expected ErrInvalidCACert on expired CA, got: %v", err)
	}

	// 3. Unconstrained CA (no PermittedDNSDomains) must be rejected
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	unconstrainedTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Unconstrained Root"},
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, unconstrainedTmpl, unconstrainedTmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	unconstrainedCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privDER, _ := x509.MarshalECPrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})

	if _, err := pki.ParseCA(unconstrainedCertPEM, privPEM); !errors.Is(err, pki.ErrInvalidCACert) {
		t.Fatalf("expected ErrInvalidCACert for unconstrained CA, got: %v", err)
	}

	// 4. Non-CA leaf cert passed to ParseCA must be rejected
	leafTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "leaf.alt"},
		NotBefore:             time.Now().UTC().Add(-time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		PermittedDNSDomains:   []string{".alt", "alt"},
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, &priv.PublicKey, priv)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	if _, err := pki.ParseCA(leafPEM, privPEM); !errors.Is(err, pki.ErrInvalidCACert) {
		t.Fatalf("expected ErrInvalidCACert for non-CA certificate, got: %v", err)
	}

	// 5. Group/world readable ca.key on disk must be rejected
	dir := t.TempDir()
	if _, err := pki.LoadOrCreateCAForTLD(dir, "alt"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "ca.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := pki.LoadOrCreateCAForTLD(dir, "alt"); !errors.Is(err, pki.ErrInsecureKeyPerms) {
		t.Fatalf("expected ErrInsecureKeyPerms for 0644 ca.key, got: %v", err)
	}
}
