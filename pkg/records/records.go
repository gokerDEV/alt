package records

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"alt/pkg/names"
)

const (
	SchemaOwnershipV1 = "alt.ownership.v1"
	SchemaTargetV1    = "alt.target.v1"

	TargetModeHTTPS = "https"
	TargetModeP2P   = "p2p"

	Ed25519KeyPrefix = "ed25519:"
)

var (
	ErrInvalidSchema      = errors.New("records: invalid or unsupported schema")
	ErrInvalidDomain      = errors.New("records: invalid domain name")
	ErrInvalidPublicKey   = errors.New("records: invalid ed25519 public key format")
	ErrInvalidSignature   = errors.New("records: signature verification failed")
	ErrRecordExpired      = errors.New("records: record has expired")
	ErrFutureIssuedAt     = errors.New("records: record issuedAt is in the future")
	ErrInvalidGeneration  = errors.New("records: invalid generation number")
	ErrInvalidSequence    = errors.New("records: invalid sequence number")
	ErrDomainMismatch     = errors.New("records: target domain does not match ownership domain")
	ErrGenerationMismatch = errors.New("records: target ownershipGeneration does not match ownership generation")
	ErrInvalidTargetMode  = errors.New("records: invalid target mode or missing mode-specific fields")
)

// OwnershipCertificate represents an authority-signed domain ownership allocation (§7.1).
type OwnershipCertificate struct {
	Schema         string `json:"schema"`
	Domain         string `json:"domain"`
	AccountID      string `json:"accountId"`
	OwnerPublicKey string `json:"ownerPublicKey"`
	Generation     uint64 `json:"generation"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
	IssuerKeyID    string `json:"issuerKeyId"`
	Signature      string `json:"signature"`
}

// canonicalOwnership is the ordered representation of OwnershipCertificate without the signature field.
type canonicalOwnership struct {
	Schema         string `json:"schema"`
	Domain         string `json:"domain"`
	AccountID      string `json:"accountId"`
	OwnerPublicKey string `json:"ownerPublicKey"`
	Generation     uint64 `json:"generation"`
	IssuedAt       string `json:"issuedAt"`
	ExpiresAt      string `json:"expiresAt"`
	IssuerKeyID    string `json:"issuerKeyId"`
}

// TargetRecord represents an owner-signed routing target for a .alt domain (§7.2).
type TargetRecord struct {
	Schema              string   `json:"schema"`
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

// canonicalTarget is the ordered representation of TargetRecord without the signature field.
type canonicalTarget struct {
	Schema              string   `json:"schema"`
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
func (c *OwnershipCertificate) SigningBytes() ([]byte, error) {
	payload, err := json.Marshal(canonicalOwnership{
		Schema:         c.Schema,
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
	return append([]byte(SchemaOwnershipV1+"\x00"), payload...), nil
}

// Sign signs the OwnershipCertificate using the registry authority's Ed25519 private key.
func (c *OwnershipCertificate) Sign(authorityPriv ed25519.PrivateKey) error {
	if c.Schema == "" {
		c.Schema = SchemaOwnershipV1
	}
	msg, err := c.SigningBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(authorityPriv, msg)
	c.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks the schema, field invariants, validity window, and authority Ed25519 signature.
func (c *OwnershipCertificate) Verify(authorityPub ed25519.PublicKey, now time.Time) error {
	return c.VerifyForTLD(authorityPub, now, names.DefaultTLD)
}

// VerifyForTLD verifies an ownership certificate for the selected namespace.
func (c *OwnershipCertificate) VerifyForTLD(authorityPub ed25519.PublicKey, now time.Time, tld string) error {
	if c.Schema != SchemaOwnershipV1 {
		return ErrInvalidSchema
	}
	if !names.IsDomain(c.Domain, tld) {
		return ErrInvalidDomain
	}
	if c.Generation == 0 {
		return ErrInvalidGeneration
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
	if !ed25519.Verify(authorityPub, msg, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// SigningBytes returns the domain-separated canonical byte representation of TargetRecord.
func (r *TargetRecord) SigningBytes() ([]byte, error) {
	payload, err := json.Marshal(canonicalTarget{
		Schema:              r.Schema,
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
	return append([]byte(SchemaTargetV1+"\x00"), payload...), nil
}

// Sign signs the TargetRecord using the domain owner's Ed25519 private key.
func (r *TargetRecord) Sign(ownerPriv ed25519.PrivateKey) error {
	if r.Schema == "" {
		r.Schema = SchemaTargetV1
	}
	msg, err := r.SigningBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ownerPriv, msg)
	r.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify Against Ownership validates the TargetRecord against a verified OwnershipCertificate.
func (r *TargetRecord) Verify(cert *OwnershipCertificate, now time.Time) error {
	if r.Schema != SchemaTargetV1 {
		return ErrInvalidSchema
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
		if !strings.HasPrefix(r.Target, "https://") || r.PublisherIdentity != "" || len(r.SignalingEndpoints) > 0 {
			return ErrInvalidTargetMode
		}
	case TargetModeP2P:
		if r.Target != "" || len(r.SignalingEndpoints) == 0 {
			return ErrInvalidTargetMode
		}
		if _, err := ParsePublicKey(r.PublisherIdentity); err != nil {
			return fmt.Errorf("%w: invalid publisherIdentity", ErrInvalidTargetMode)
		}
		for _, ep := range r.SignalingEndpoints {
			if !strings.HasPrefix(ep, "wss://") {
				return fmt.Errorf("%w: signaling endpoint must use wss://", ErrInvalidTargetMode)
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

func verifyTimestamps(issuedAtStr, expiresAtStr string, now time.Time) error {
	issuedAt, err := time.Parse(time.RFC3339, issuedAtStr)
	if err != nil {
		return fmt.Errorf("records: invalid issuedAt timestamp: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		return fmt.Errorf("records: invalid expiresAt timestamp: %w", err)
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
