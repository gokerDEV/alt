package pki_test

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"

	"alt/pkg/pki"
)

func TestDeviceCAAndLeafVerification(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCA failed: %v", err)
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

