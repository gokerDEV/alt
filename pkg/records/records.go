package records

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"alt/pkg/names"
	"alt/pkg/profile"
)

const (
	SchemaOwnershipV1    = "alt.ownership.v1"
	SchemaTargetV1       = "alt.target.v1"
	SchemaKeyChallengeV1 = "alt.key-challenge.v1"

	KeyChallengePurposeBindOwnerKey = "bind_owner_key"

	TargetModeHTTPS = "https"
	TargetModeP2P   = "p2p"

	Ed25519KeyPrefix = "ed25519:"
)

var (
	ErrInvalidSchema      = errors.New("records: invalid or unsupported schema")
	ErrInvalidNetworkID   = errors.New("records: missing or mismatched networkId")
	ErrInvalidDomain      = errors.New("records: invalid domain name")
	ErrInvalidPublicKey   = errors.New("records: invalid ed25519 public key format")
	ErrInvalidSignature   = errors.New("records: signature verification failed")
	ErrUnknownIssuerKey   = errors.New("records: unknown or untrusted issuerKeyId")
	ErrRecordExpired      = errors.New("records: record has expired")
	ErrFutureIssuedAt     = errors.New("records: record issuedAt is in the future")
	ErrInvalidValidityWin = errors.New("records: expiresAt must be strictly after issuedAt")
	ErrInvalidGeneration  = errors.New("records: invalid generation number")
	ErrInvalidSequence    = errors.New("records: invalid sequence number")
	ErrDomainMismatch     = errors.New("records: target domain does not match ownership domain")
	ErrGenerationMismatch = errors.New("records: target ownershipGeneration does not match ownership generation")
	ErrInvalidTargetMode  = errors.New("records: invalid target mode or invalid endpoint URL")
)

// OwnershipCertificate represents an authority-signed domain ownership allocation (§6, §7.1).
type OwnershipCertificate struct {
	Schema         string `json:"schema"`
	NetworkID      string `json:"networkId"`
	Domain         string `json:"domain"`
	AccountID      string `json:"accountId"`
	OwnerPublicKey string `json:"ownerPublicKey"`
	Generation     uint64 `json:"generation"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
	IssuerKeyID    string `json:"issuerKeyId"`
	Signature      string `json:"signature"`
}

// Clone returns a deep copy of OwnershipCertificate.
func (c *OwnershipCertificate) Clone() *OwnershipCertificate {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// canonicalOwnership is the ordered representation of OwnershipCertificate without the signature field.
type canonicalOwnership struct {
	Schema         string `json:"schema"`
	NetworkID      string `json:"networkId"`
	Domain         string `json:"domain"`
	AccountID      string `json:"accountId"`
	OwnerPublicKey string `json:"ownerPublicKey"`
	Generation     uint64 `json:"generation"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
	IssuerKeyID    string `json:"issuerKeyId"`
}

// TargetRecord represents an owner-signed routing target for a namespace domain (§6, §7.2).
type TargetRecord struct {
	Schema              string   `json:"schema"`
	NetworkID           string   `json:"networkId"`
	Domain              string   `json:"domain"`
	OwnershipGeneration uint64   `json:"ownershipGeneration"`
	Sequence            uint64   `json:"sequence"`
	Mode                string   `json:"mode"`
	Target              string   `json:"target,omitempty"`
	PublisherIdentity   string   `json:"publisherIdentity,omitempty"`
	SignalingEndpoints  []string `json:"signalingEndpoints,omitempty"`
	IssuedAt            string   `json:"issuedAt"`
	ExpiresAt           string   `json:"expiresAt"`
	Signature           string   `json:"signature"`
}

// Clone returns a deep copy of TargetRecord (including SignalingEndpoints slice).
func (r *TargetRecord) Clone() *TargetRecord {
	if r == nil {
		return nil
	}
	cp := *r
	if r.SignalingEndpoints != nil {
		cp.SignalingEndpoints = append([]string(nil), r.SignalingEndpoints...)
	}
	return &cp
}

// canonicalTarget is the ordered representation of TargetRecord without the signature field.
type canonicalTarget struct {
	Schema              string   `json:"schema"`
	NetworkID           string   `json:"networkId"`
	Domain              string   `json:"domain"`
	OwnershipGeneration uint64   `json:"ownershipGeneration"`
	Sequence            uint64   `json:"sequence"`
	Mode                string   `json:"mode"`
	Target              string   `json:"target,omitempty"`
	PublisherIdentity   string   `json:"publisherIdentity,omitempty"`
	SignalingEndpoints  []string `json:"signalingEndpoints,omitempty"`
	IssuedAt            string   `json:"issuedAt"`
	ExpiresAt           string   `json:"expiresAt"`
}

// KeyChallengePayload represents the single-use CLI owner-key binding challenge payload
// signed over `alt.key-challenge.v1\x00<networkId>\x00<compact-json>`.
type KeyChallengePayload struct {
	AccountID      string `json:"accountId"`
	OwnerPublicKey string `json:"ownerPublicKey"`
	Nonce          string `json:"nonce"`
	Purpose        string `json:"purpose"`
	ExpiresAt      string `json:"expiresAt"`
}

// SigningBytes returns the domain-separated canonical byte representation of KeyChallengePayload.
func (p *KeyChallengePayload) SigningBytes(networkID string) ([]byte, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, ErrInvalidNetworkID
	}
	if _, err := ParsePublicKey(p.OwnerPublicKey); err != nil {
		return nil, err
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", p.ExpiresAt); err != nil {
		return nil, fmt.Errorf("records: challenge expiresAt must use whole-second UTC RFC3339: %w", err)
	}
	payload, err := json.Marshal(KeyChallengePayload{
		AccountID:      p.AccountID,
		OwnerPublicKey: p.OwnerPublicKey,
		Nonce:          p.Nonce,
		Purpose:        p.Purpose,
		ExpiresAt:      p.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	prefix := SchemaKeyChallengeV1 + "\x00" + networkID + "\x00"
	return append([]byte(prefix), payload...), nil
}

// Sign signs the KeyChallengePayload with the owner's Ed25519 private key and returns standard padded Base64.
func (p *KeyChallengePayload) Sign(networkID string, ownerPriv ed25519.PrivateKey) (string, error) {
	msg, err := p.SigningBytes(networkID)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(ownerPriv, msg)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// Verify checks the Ed25519 signature over KeyChallengePayload for the expected networkID.
func (p *KeyChallengePayload) Verify(networkID, signatureBase64 string) error {
	ownerPub, err := ParsePublicKey(p.OwnerPublicKey)
	if err != nil {
		return err
	}
	msg, err := p.SigningBytes(networkID)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(ownerPub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// DecodeOwnershipStrict parses JSON strictly (rejecting unknown fields and trailing tokens).
func DecodeOwnershipStrict(raw []byte) (*OwnershipCertificate, error) {
	var cert OwnershipCertificate
	if err := decodeStrictJSON(raw, &cert); err != nil {
		return nil, err
	}
	return &cert, nil
}

// DecodeTargetStrict parses JSON strictly (rejecting unknown fields and trailing tokens).
func DecodeTargetStrict(raw []byte) (*TargetRecord, error) {
	var target TargetRecord
	if err := decodeStrictJSON(raw, &target); err != nil {
		return nil, err
	}
	return &target, nil
}

func decodeStrictJSON(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("records: malformed JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("records: trailing data after JSON object")
	}
	return nil
}

// FormatPublicKey encodes an ed25519.PublicKey as "ed25519:<base64>".
func FormatPublicKey(pub ed25519.PublicKey) string {
	return Ed25519KeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParsePublicKey decodes an "ed25519:<base64>" string into an ed25519.PublicKey.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(encoded, Ed25519KeyPrefix) {
		return nil, ErrInvalidPublicKey
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, Ed25519KeyPrefix))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPublicKey
	}
	return ed25519.PublicKey(raw), nil
}

// SigningBytes returns the domain-separated canonical byte representation of OwnershipCertificate.
// Both the domain-separation prefix and the signed JSON payload include networkId (PLAN.md §3.B).
func (c *OwnershipCertificate) SigningBytes() ([]byte, error) {
	if strings.TrimSpace(c.NetworkID) == "" {
		return nil, ErrInvalidNetworkID
	}
	payload, err := json.Marshal(canonicalOwnership{
		Schema:         c.Schema,
		NetworkID:      c.NetworkID,
		Domain:         c.Domain,
		AccountID:      c.AccountID,
		OwnerPublicKey: c.OwnerPublicKey,
		Generation:     c.Generation,
		IssuedAt:       c.IssuedAt,
		ExpiresAt:      c.ExpiresAt,
		IssuerKeyID:    c.IssuerKeyID,
	})
	if err != nil {
		return nil, err
	}
	prefix := SchemaOwnershipV1 + "\x00" + c.NetworkID + "\x00"
	return append([]byte(prefix), payload...), nil
}

// Sign signs the OwnershipCertificate using the registry authority's Ed25519 private key.
func (c *OwnershipCertificate) Sign(authorityPriv ed25519.PrivateKey) error {
	if c.Schema == "" {
		c.Schema = SchemaOwnershipV1
	}
	if c.NetworkID == "" {
		c.NetworkID = profile.DefaultNetworkID
	}
	msg, err := c.SigningBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(authorityPriv, msg)
	c.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks the schema, default network ID, default .alt namespace, validity window, and authority signature.
func (c *OwnershipCertificate) Verify(authorityPub ed25519.PublicKey, now time.Time) error {
	return c.VerifyForNetwork(authorityPub, now, profile.DefaultNetworkID, names.DefaultTLD)
}

// VerifyForTLD verifies an ownership certificate for the selected TLD under the default network ID (or TLD-local network ID).
func (c *OwnershipCertificate) VerifyForTLD(authorityPub ed25519.PublicKey, now time.Time, tld string) error {
	expectedNetwork := profile.DefaultNetworkID
	if normTLD, err := names.NormalizeTLD(tld); err == nil && normTLD != names.DefaultTLD {
		expectedNetwork = normTLD + "-local-v1"
	}
	return c.VerifyForNetwork(authorityPub, now, expectedNetwork, tld)
}

// VerifyForProfile verifies an ownership certificate against the network profile's networkId, TLD, and registry keys.
func (c *OwnershipCertificate) VerifyForProfile(prof *profile.Profile, now time.Time) error {
	if prof == nil {
		return ErrInvalidNetworkID
	}
	pub, ok := prof.AuthorityKey(c.IssuerKeyID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownIssuerKey, c.IssuerKeyID)
	}
	return c.VerifyForNetwork(pub, now, prof.NetworkID, prof.TLD)
}

// VerifyForNetwork verifies an ownership certificate for an explicit network ID and TLD.
func (c *OwnershipCertificate) VerifyForNetwork(authorityPub ed25519.PublicKey, now time.Time, networkID, tld string) error {
	if c.Schema != SchemaOwnershipV1 {
		return ErrInvalidSchema
	}
	if networkID == "" || c.NetworkID != networkID {
		return fmt.Errorf("%w: got %q, want %q", ErrInvalidNetworkID, c.NetworkID, networkID)
	}
	if !names.IsDomain(c.Domain, tld) {
		return ErrInvalidDomain
	}
	if c.Generation == 0 {
		return ErrInvalidGeneration
	}
	if strings.TrimSpace(c.IssuerKeyID) == "" {
		return ErrUnknownIssuerKey
	}
	if _, err := ParsePublicKey(c.OwnerPublicKey); err != nil {
		return err
	}
	if err := verifyTimestamps(c.IssuedAt, c.ExpiresAt, now); err != nil {
		return err
	}

	msg, err := c.SigningBytes()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if len(authorityPub) != ed25519.PublicKeySize || !ed25519.Verify(authorityPub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// SigningBytes returns the domain-separated canonical byte representation of TargetRecord.
// Both the domain-separation prefix and the signed JSON payload include networkId (PLAN.md §3.B).
func (r *TargetRecord) SigningBytes() ([]byte, error) {
	if strings.TrimSpace(r.NetworkID) == "" {
		return nil, ErrInvalidNetworkID
	}
	payload, err := json.Marshal(canonicalTarget{
		Schema:              r.Schema,
		NetworkID:           r.NetworkID,
		Domain:              r.Domain,
		OwnershipGeneration: r.OwnershipGeneration,
		Sequence:            r.Sequence,
		Mode:                r.Mode,
		Target:              r.Target,
		PublisherIdentity:   r.PublisherIdentity,
		SignalingEndpoints:  r.SignalingEndpoints,
		IssuedAt:            r.IssuedAt,
		ExpiresAt:           r.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	prefix := SchemaTargetV1 + "\x00" + r.NetworkID + "\x00"
	return append([]byte(prefix), payload...), nil
}

// Sign signs the TargetRecord using the domain owner's Ed25519 private key.
func (r *TargetRecord) Sign(ownerPriv ed25519.PrivateKey) error {
	if r.Schema == "" {
		r.Schema = SchemaTargetV1
	}
	if r.NetworkID == "" {
		r.NetworkID = profile.DefaultNetworkID
	}
	msg, err := r.SigningBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ownerPriv, msg)
	r.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify validates the TargetRecord against a verified OwnershipCertificate (including networkId binding).
func (r *TargetRecord) Verify(cert *OwnershipCertificate, now time.Time) error {
	if r.Schema != SchemaTargetV1 {
		return ErrInvalidSchema
	}
	if cert == nil || cert.NetworkID == "" || r.NetworkID != cert.NetworkID {
		return ErrInvalidNetworkID
	}
	if r.Domain != cert.Domain {
		return ErrDomainMismatch
	}
	if r.OwnershipGeneration != cert.Generation {
		return ErrGenerationMismatch
	}
	if r.Sequence == 0 {
		return ErrInvalidSequence
	}

	switch r.Mode {
	case TargetModeHTTPS:
		if r.PublisherIdentity != "" || len(r.SignalingEndpoints) > 0 {
			return ErrInvalidTargetMode
		}
		if err := validateStrictEndpointURL(r.Target, "https"); err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidTargetMode, err)
		}
	case TargetModeP2P:
		if r.Target != "" || len(r.SignalingEndpoints) == 0 {
			return ErrInvalidTargetMode
		}
		if _, err := ParsePublicKey(r.PublisherIdentity); err != nil {
			return fmt.Errorf("%w: invalid publisherIdentity", ErrInvalidTargetMode)
		}
		for _, ep := range r.SignalingEndpoints {
			if err := validateStrictEndpointURL(ep, "wss"); err != nil {
				return fmt.Errorf("%w: %v", ErrInvalidTargetMode, err)
			}
		}
	default:
		return ErrInvalidTargetMode
	}

	if err := verifyTimestamps(r.IssuedAt, r.ExpiresAt, now); err != nil {
		return err
	}

	ownerPub, err := ParsePublicKey(cert.OwnerPublicKey)
	if err != nil {
		return err
	}

	msg, err := r.SigningBytes()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(ownerPub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// validateStrictEndpointURL enforces URL scheme, host presence, port range (1..65535),
// and forbids userinfo, query strings, fragments, and whitespace/control characters.
func validateStrictEndpointURL(rawURL, expectedScheme string) error {
	if rawURL == "" || strings.TrimSpace(rawURL) != rawURL || strings.ContainsAny(rawURL, " \t\r\n") {
		return errors.New("URL must not be empty or contain whitespace")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	if u.Scheme != expectedScheme {
		return fmt.Errorf("scheme must be %s", expectedScheme)
	}
	if u.Opaque != "" || u.Host == "" {
		return errors.New("host is required")
	}
	if u.User != nil {
		return errors.New("userinfo is not allowed in target/signaling URLs")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("query parameters are not allowed in target/signaling URLs")
	}
	if u.Fragment != "" || strings.Contains(rawURL, "#") {
		return errors.New("fragments are not allowed in target/signaling URLs")
	}

	hostname := u.Hostname()
	if hostname == "" {
		return errors.New("hostname is required")
	}
	if portStr := u.Port(); portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return errors.New("port must be between 1 and 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("empty port suffix is not allowed")
	}

	// Reject malformed bracketed IPv6 literals or empty DNS labels
	if strings.Contains(u.Host, "[") || strings.Contains(u.Host, "]") {
		if net.ParseIP(hostname) == nil {
			return errors.New("invalid IPv6 literal in host")
		}
	} else if net.ParseIP(hostname) == nil {
		if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") || strings.Contains(hostname, "..") {
			return errors.New("invalid DNS hostname")
		}
	}
	return nil
}

func verifyTimestamps(issuedAtStr, expiresAtStr string, now time.Time) error {
	issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		return fmt.Errorf("records: invalid issuedAt timestamp: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return fmt.Errorf("records: invalid expiresAt timestamp: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return ErrInvalidValidityWin
	}
	// Allow up to 5 minutes clock skew for issuedAt
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return ErrFutureIssuedAt
	}
	if !now.Before(expiresAt) {
		return ErrRecordExpired
	}
	return nil
}

// ReferenceValidTime returns a timestamp guaranteed to lie within [issuedAt, expiresAt)
// when issuedAt < expiresAt, allowing callers restoring persisted monotonic state from disk
// to re-verify cryptographic signatures even after wall-clock expiry.
func ReferenceValidTime(issuedAtStr, expiresAtStr string) (time.Time, error) {
	issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("records: invalid issuedAt timestamp: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("records: invalid expiresAt timestamp: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return time.Time{}, ErrInvalidValidityWin
	}
	return issuedAt, nil
}
