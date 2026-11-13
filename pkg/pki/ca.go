package pki

import (
	"bytes"
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
	ErrInvalidCACert     = errors.New("pki: invalid or unconstrained CA certificate")
	ErrInvalidCAKey      = errors.New("pki: invalid or mismatched CA private key")
	ErrInsecureKeyPerms  = errors.New("pki: CA private key has insecure group/world permissions")
)

// CA represents a device-local Root Certificate Authority restricted to the configured TLD (§4.2).
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
		NotBefore:                   now.Add(-1 * time.Hour),
		NotAfter:                    now.AddDate(10, 0, 0),
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid:       true,
		IsCA:                        true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{"." + tld, tld},
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

// LoadOrCreateCA loads an existing default-.alt CA from dir or generates and saves a new one.
func LoadOrCreateCA(dir string) (*CA, error) {
	return LoadOrCreateCAForTLD(dir, names.DefaultTLD)
}

// LoadOrCreateCAForTLD loads an existing CA constrained to tldValue from dir (verifying private key
// file permissions, certificate constraints, and keypair match) or creates a new one with 0600 permissions.
func LoadOrCreateCAForTLD(dir, tldValue string) (*CA, error) {
	tld, err := names.NormalizeTLD(tldValue)
	if err != nil {
		return nil, err
	}

	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	certInfo, certStatErr := os.Stat(certPath)
	keyInfo, keyStatErr := os.Stat(keyPath)
	if certStatErr == nil && keyStatErr == nil {
		if !certInfo.Mode().IsRegular() || !keyInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: CA files must be regular files", ErrInvalidCACert)
		}
		if keyInfo.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: %s has mode %04o (must not be group/world accessible)", ErrInsecureKeyPerms, keyPath, keyInfo.Mode().Perm())
		}
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		ca, err := ParseCA(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		if ca.tld != tld {
			return nil, fmt.Errorf("%w: CA in %s is constrained to .%s, want .%s", ErrInvalidCACert, dir, ca.tld, tld)
		}
		return ca, nil
	}
	if !os.IsNotExist(certStatErr) || !os.IsNotExist(keyStatErr) {
		return nil, fmt.Errorf("pki: incomplete or unreadable CA state in %s", dir)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca, newKeyPEM, err := GenerateCAForTLD(tld)
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

// ParseCA reconstructs and strictly validates a CA instance from PEM-encoded certificate and private key bytes.
func ParseCA(certPEM, keyPEM []byte) (*CA, error) {
	return ParseCAAt(certPEM, keyPEM, time.Now().UTC())
}

// ParseCAAt reconstructs and strictly validates a CA instance at the provided reference time.
func ParseCAAt(certPEM, keyPEM []byte, now time.Time) (*CA, error) {
	cBlock, restCert := pem.Decode(certPEM)
	if cBlock == nil || cBlock.Type != "CERTIFICATE" || len(bytes.TrimSpace(restCert)) != 0 {
		return nil, fmt.Errorf("%w: expected single PEM CERTIFICATE block", ErrInvalidCACert)
	}
	cert, err := x509.ParseCertificate(cBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCACert, err)
	}

	kBlock, restKey := pem.Decode(keyPEM)
	if kBlock == nil || len(bytes.TrimSpace(restKey)) != 0 {
		return nil, fmt.Errorf("%w: expected single PEM private key block", ErrInvalidCAKey)
	}
	priv, err := parseECDSAPrivateKeyBlock(kBlock)
	if err != nil {
		return nil, err
	}

	tld, err := validateCACertAndKey(cert, priv, now)
	if err != nil {
		return nil, err
	}

	return &CA{
		cert:      cert,
		privKey:   priv,
		certPEM:   certPEM,
		tld:       tld,
		leafCache: make(map[string]*tls.Certificate),
	}, nil
}

func parseECDSAPrivateKeyBlock(block *pem.Block) (*ecdsa.PrivateKey, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCAKey, err)
		}
		return priv, nil
	case "PRIVATE KEY":
		anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidCAKey, err)
		}
		priv, ok := anyKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%w: PKCS#8 key is not ECDSA", ErrInvalidCAKey)
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("%w: unsupported PEM block type %q", ErrInvalidCAKey, block.Type)
	}
}

func validateCACertAndKey(cert *x509.Certificate, priv *ecdsa.PrivateKey, now time.Time) (string, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return "", fmt.Errorf("%w: CA key must be ECDSA P-256", ErrInvalidCAKey)
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPub.Equal(&priv.PublicKey) {
		return "", fmt.Errorf("%w: CA certificate public key does not match private key", ErrInvalidCAKey)
	}

	if !cert.BasicConstraintsValid || !cert.IsCA {
		return "", fmt.Errorf("%w: certificate is not a valid CA", ErrInvalidCACert)
	}
	if cert.MaxPathLen > 0 || (cert.MaxPathLen == 0 && !cert.MaxPathLenZero) {
		return "", fmt.Errorf("%w: CA must enforce MaxPathLen=0", ErrInvalidCACert)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return "", fmt.Errorf("%w: CA certificate missing KeyUsageCertSign", ErrInvalidCACert)
	}
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return "", fmt.Errorf("%w: CA certificate is expired or not yet valid", ErrInvalidCACert)
	}
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return "", fmt.Errorf("%w: CA certificate is not validly self-signed: %v", ErrInvalidCACert, err)
	}

	tld, err := validatePermittedNamespace(cert)
	if err != nil {
		return "", err
	}
	return tld, nil
}

func validatePermittedNamespace(cert *x509.Certificate) (string, error) {
	if len(cert.PermittedDNSDomains) == 0 {
		return "", fmt.Errorf("%w: CA certificate must have PermittedDNSDomains name constraints", ErrInvalidCACert)
	}
	if len(cert.PermittedIPRanges) > 0 || len(cert.PermittedURIDomains) > 0 || len(cert.PermittedEmailAddresses) > 0 {
		return "", fmt.Errorf("%w: unexpected non-DNS name constraints on CA", ErrInvalidCACert)
	}

	var inferredTLD string
	for _, rawPerm := range cert.PermittedDNSDomains {
		trimmed := strings.TrimSpace(rawPerm)
		if trimmed == "" {
			return "", fmt.Errorf("%w: empty PermittedDNSDomains entry", ErrInvalidCACert)
		}
		candidateTLD, err := names.NormalizeTLD(trimmed)
		if err != nil {
			return "", fmt.Errorf("%w: invalid PermittedDNSDomains entry %q", ErrInvalidCACert, rawPerm)
		}
		if rawPerm != candidateTLD && rawPerm != "."+candidateTLD {
			return "", fmt.Errorf("%w: non-canonical PermittedDNSDomains entry %q", ErrInvalidCACert, rawPerm)
		}
		if inferredTLD == "" {
			inferredTLD = candidateTLD
		} else if inferredTLD != candidateTLD {
			return "", fmt.Errorf("%w: CA PermittedDNSDomains spans multiple TLDs (%q and %q)", ErrInvalidCACert, inferredTLD, candidateTLD)
		}
	}
	return inferredTLD, nil
}

// TLD returns the single DNS TLD to which this CA is constrained.
func (ca *CA) TLD() string {
	return ca.tld
}

// CertPEM returns a copy of the PEM-encoded public CA certificate.
func (ca *CA) CertPEM() []byte {
	return append([]byte(nil), ca.certPEM...)
}

// Certificate returns the parsed x509 Root CA certificate.
func (ca *CA) Certificate() *x509.Certificate {
	return ca.cert
}

// IssueLeaf issues (or returns a cached) leaf TLS certificate for a valid namespace hostname.
func (ca *CA) IssueLeaf(hostname string) (*tls.Certificate, error) {
	host := strings.ToLower(strings.TrimSpace(hostname))
	if !names.IsDomain(host, ca.tld) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedDomain, hostname)
	}

	now := time.Now().UTC()
	ca.mu.RLock()
	if cached, ok := ca.leafCache[host]; ok && cached.Leaf != nil && now.Add(time.Hour).Before(cached.Leaf.NotAfter) {
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

// GetCertificate implements the crypto/tls Config.GetCertificate callback for SNI-based leaf issuance.
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
