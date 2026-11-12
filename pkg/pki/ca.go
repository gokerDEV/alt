package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"alt/pkg/names"
)

var (
	ErrUnsupportedDomain = errors.New("pki: certificate generation is outside the configured namespace")
)

// CA represents a device-local Root Certificate Authority restricted to the .alt TLD (§4.2).
type CA struct {
	cert    *x509.Certificate
	privKey *ecdsa.PrivateKey
	certPEM []byte
	tld     string

	mu        sync.RWMutex
	leafCache map[string]*tls.Certificate
}

// GenerateCA creates a new device-local ECDSA P-256 Root CA with NameConstraints
// permitting only the ".alt" DNS domain tree.
func GenerateCA() (*CA, []byte, error) {
	return GenerateCAForTLD(names.DefaultTLD)
}

// GenerateCAForTLD creates a device-local CA constrained to the selected namespace.
func GenerateCAForTLD(tldValue string) (*CA, []byte, error) {
	tld, err := names.NormalizeTLD(tldValue)
	if err != nil {
		return nil, nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ALT Local Development CA"},
			CommonName:   "ALT Device Local Root CA",
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		PermittedDNSDomains:   []string{"." + tld, tld},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return &CA{
		cert:      cert,
		privKey:   priv,
		certPEM:   certPEM,
		tld:       tld,
		leafCache: make(map[string]*tls.Certificate),
	}, keyPEM, nil
}

// LoadOrCreateCA loads an existing CA from dir or generates and saves a new one with strict permissions (0600 for private key).
func LoadOrCreateCA(dir string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return ParseCA(certPEM, keyPEM)
	}

	ca, newKeyPEM, err := GenerateCA()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, newKeyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.certPEM, 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

// ParseCA reconstructs a CA instance from PEM-encoded certificate and private key bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	cBlock, _ := pem.Decode(certPEM)
	if cBlock == nil {
		return nil, errors.New("pki: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, err
	}

	kBlock, _ := pem.Decode(keyPEM)
	if kBlock == nil {
		return nil, errors.New("pki: invalid CA private key PEM")
	}
	priv, err := x509.ParseECPrivateKey(kBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:      cert,
		privKey:   priv,
		certPEM:   certPEM,
		tld:       inferTLD(cert),
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

// CertPEM returns the PEM-encoded public CA certificate (safe for adding to the OS trust store).
func (ca *CA) CertPEM() []byte {
	return ca.certPEM
}

// Certificate returns the parsed x509 Root CA certificate.
func (ca *CA) Certificate() *x509.Certificate {
	return ca.cert
}

// IssueLeaf issues (or returns a cached) leaf TLS certificate for a valid .alt hostname.
func (ca *CA) IssueLeaf(hostname string) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSpace(hostname))
	if !names.IsDomain(host, ca.tld) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDomain, hostname)
	}

	ca.mu.RLock()
	if cached, ok := ca.leafCache[host]; ok {
		ca.mu.RUnlock()
		return cached, nil
	}
	ca.mu.RUnlock()

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:              []string{host},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(0, 3, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafPriv.PublicKey, ca.privKey)
	if err != nil {
		return nil, err
	}

	leafParsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  leafPriv,
		Leaf:        leafParsed,
	}

	ca.mu.Lock()
	ca.leafCache[host] = tlsCert
	ca.mu.Unlock()

	return tlsCert, nil
}

func inferTLD(cert *x509.Certificate) string {
	for _, permitted := range cert.PermittedDNSDomains {
		if tld, err := names.NormalizeTLD(permitted); err == nil {
			return tld
		}
	}
	return names.DefaultTLD
}

// GetCertificate implements the crypto/tls Config.GetCertificate callback for SNI-based .alt leaf issuance.
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil || hello.ServerName == "" {
		return nil, ErrUnsupportedDomain
	}
	return ca.IssueLeaf(hello.ServerName)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}
