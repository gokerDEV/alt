// Package resolver implements content-addressed manifest decoding,
// source-independent cryptographic verification, and monotonic record caching
// for ALT-compatible private DNS namespaces (PLAN.md §3.D, ARCHITECTURE.md §7).
package resolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	alterrors "alt/pkg/errors"
	"alt/pkg/names"
	"alt/pkg/profile"
	"alt/pkg/records"
)

const (
	// SchemaManifestV1 identifies the v1 signed-record bundle manifest.
	SchemaManifestV1 = "alt.manifest.v1"

	// MaxManifestBytes bounds untrusted manifest payloads fetched over HTTP/IPFS (1 MiB).
	MaxManifestBytes = 1 << 20
)

// RecordSource fetches raw ownership and target record JSON bytes for a domain.
// Verification never depends on the source; transport endpoints are untrusted.
type RecordSource interface {
	Resolve(ctx context.Context, domain string) (ownership []byte, target []byte, err error)
}

// ManifestEntry bundles the signed ownership certificate and target record for one domain.
type ManifestEntry struct {
	Ownership json.RawMessage `json:"ownership"`
	Target    json.RawMessage `json:"target"`
}

// Manifest represents a content-addressed directory of signed records for a network.
type Manifest struct {
	Schema    string                   `json:"schema"`
	NetworkID string                   `json:"networkId"`
	Generated string                   `json:"generatedAt,omitempty"`
	Records   map[string]ManifestEntry `json:"records"`
}

// DecodeManifestStrict parses a Manifest with strict JSON rules and size bounds.
func DecodeManifestStrict(raw []byte) (*Manifest, error) {
	if len(raw) > MaxManifestBytes {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "manifest exceeds maximum byte limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "malformed manifest JSON", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "trailing tokens after manifest JSON")
	}
	if m.Schema != SchemaManifestV1 {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, fmt.Sprintf("unsupported manifest schema %q", m.Schema))
	}
	if strings.TrimSpace(m.NetworkID) == "" {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "manifest missing networkId")
	}
	if m.Records == nil {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "manifest missing records map")
	}
	return &m, nil
}

// ComputeRawCIDv1 computes the deterministic CIDv1 (raw multicodec 0x55, sha2-256 0x12, base32lower 'b')
// for raw block bytes, matching `ipfs block put --cid-codec raw` / `ipfs add --cid-version=1 --raw-leaves`.
func ComputeRawCIDv1(data []byte) string {
	sum := sha256.Sum256(data)
	// CIDv1 binary: <version: 0x01><codec: 0x55 (raw)><mh-code: 0x12 (sha2-256)><mh-len: 0x20 (32)><32-byte digest>
	buf := make([]byte, 0, 36)
	buf = append(buf, 0x01, 0x55, 0x12, 0x20)
	buf = append(buf, sum[:]...)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return "b" + strings.ToLower(enc.EncodeToString(buf))
}

// VerifyBlockCID verifies that untrusted block bytes match the expected CIDv1 (raw + sha2-256)
// before any JSON decoding or record processing takes place.
func VerifyBlockCID(expectedCID string, data []byte) error {
	cid := strings.TrimSpace(expectedCID)
	if !strings.HasPrefix(cid, "b") || len(cid) < 10 {
		return alterrors.New(alterrors.CodeRecordUnavailable, "unsupported CID format: expected base32 CIDv1 starting with 'b'")
	}

	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := enc.DecodeString(strings.ToUpper(cid[1:]))
	if err != nil {
		return alterrors.Wrap(alterrors.CodeRecordUnavailable, "invalid base32 CIDv1", err)
	}
	if len(decoded) != 36 || decoded[0] != 0x01 {
		return alterrors.New(alterrors.CodeRecordUnavailable, "unsupported CIDv1 multicodec or multihash length (expected raw + sha2-256)")
	}
	if decoded[1] != 0x55 {
		return alterrors.New(alterrors.CodeRecordUnavailable, fmt.Sprintf("unsupported CIDv1 codec 0x%x: expected raw (0x55)", decoded[1]))
	}
	if decoded[2] != 0x12 || decoded[3] != 0x20 {
		return alterrors.New(alterrors.CodeRecordUnavailable, "unsupported CIDv1 multihash: expected sha2-256")
	}

	sum := sha256.Sum256(data)
	if !bytes.Equal(decoded[4:], sum[:]) {
		return alterrors.New(alterrors.CodeRecordUnavailable, "IPFS content-addressing hash mismatch for CID "+cid)
	}
	return nil
}

// VerifiedResolution holds a fully verified ownership + target pair.
type VerifiedResolution struct {
	Ownership *records.OwnershipCertificate
	Target    *records.TargetRecord
	FromCache bool
}

// Clone returns a deep copy of VerifiedResolution so callers cannot mutate cached records.
func (v VerifiedResolution) Clone() VerifiedResolution {
	return VerifiedResolution{
		Ownership: v.Ownership.Clone(),
		Target:    v.Target.Clone(),
		FromCache: v.FromCache,
	}
}

// Config configures optional construction-time settings for Resolver so trust roots
// and clocks remain immutable after construction.
type Config struct {
	Profile              *profile.Profile
	Source               RecordSource
	FallbackAuthorityKey ed25519.PublicKey
	Clock                func() time.Time
}

// Resolver verifies records from a RecordSource against an immutable snapshot of a network Profile
// and maintains an atomic, monotonic anti-rollback cache (PLAN.md §3.D, ARCHITECTURE.md §7).
// A zero-value or nil *Resolver is invalid and fails closed on all operations.
type Resolver struct {
	initialized bool
	profile     *profile.Profile
	fallbackKey ed25519.PublicKey
	source      RecordSource
	nowFn       func() time.Time
	initErr     error
	sealed      bool

	mu    sync.RWMutex
	cache map[string]VerifiedResolution
}

// NewChecked creates a new Resolver and returns CodeInvalidConfig if cfg.Profile fails validation.
func NewChecked(cfg Config) (*Resolver, error) {
	var cloned *profile.Profile
	if cfg.Profile == nil {
		cloned = profile.Default()
		if err := cloned.Validate(); err != nil {
			return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "invalid default network profile", err)
		}
	} else {
		cloned = cfg.Profile.Clone()
		if err := cloned.Validate(); err != nil {
			return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "invalid network profile for resolver", err)
		}
	}
	var fbKey ed25519.PublicKey
	if len(cfg.FallbackAuthorityKey) == ed25519.PublicKeySize {
		fbKey = append(ed25519.PublicKey(nil), cfg.FallbackAuthorityKey...)
	} else if len(cfg.FallbackAuthorityKey) != 0 {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "invalid FallbackAuthorityKey length")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Resolver{
		initialized: true,
		profile:     cloned,
		fallbackKey: fbKey,
		source:      cfg.Source,
		nowFn:       clock,
		cache:       make(map[string]VerifiedResolution),
	}, nil
}

// New creates a new Resolver bound to a validated clone of prof and optional source.
//
// Deprecated: Use NewChecked instead so invalid profiles return an explicit error at construction.
// If prof fails validation, the returned Resolver records InitError() and fails closed on all operations.
func New(prof *profile.Profile, source RecordSource) *Resolver {
	return NewWithConfig(Config{
		Profile: prof,
		Source:  source,
	})
}

// NewWithConfig creates a new Resolver with construction-time profile, source, fallback key, and clock.
//
// Deprecated: Use NewChecked instead so invalid profiles or keys return an explicit error at construction.
// If cfg fails validation, the returned Resolver fails closed on all operations with CodeInvalidConfig.
func NewWithConfig(cfg Config) *Resolver {
	res, err := NewChecked(cfg)
	if err == nil {
		return res
	}
	return &Resolver{
		initErr: err,
	}
}

// InitError returns CodeInvalidConfig if the Resolver is nil, zero-value/uninitialized,
// or failed profile/key validation during New / NewWithConfig.
func (r *Resolver) InitError() error {
	if r == nil {
		return alterrors.New(alterrors.CodeInvalidConfig, "nil resolver")
	}
	if r.initErr != nil {
		return r.initErr
	}
	if !r.initialized || r.profile == nil || r.nowFn == nil || r.cache == nil {
		return alterrors.New(alterrors.CodeInvalidConfig, "uninitialized zero-value resolver")
	}
	return nil
}

// Seal permanently freezes runtime clock overrides on the Resolver once attached to an Engine.
func (r *Resolver) Seal() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.sealed = true
	r.mu.Unlock()
}

// SetClock overrides the wall clock for deterministic unit tests prior to Seal().
// Once sealed by an Engine, SetClock is a no-op so external holders cannot bypass expiry checks.
func (r *Resolver) SetClock(fn func() time.Time) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.sealed && fn != nil {
		r.nowFn = fn
	}
}

// FallbackAuthorityKey returns a copy of the optional legacy single-key fallback, if configured.
func (r *Resolver) FallbackAuthorityKey() ed25519.PublicKey {
	if r == nil || len(r.fallbackKey) == 0 {
		return nil
	}
	return append(ed25519.PublicKey(nil), r.fallbackKey...)
}

// Profile returns a cloned copy of the resolver's bound network profile,
// or nil if the resolver is invalid/poisoned or uninitialized.
func (r *Resolver) Profile() *profile.Profile {
	if r == nil || r.InitError() != nil {
		return nil
	}
	return r.profile.Clone()
}

// Ingest verifies and stores an ownership certificate and target record using the resolver's clock.
func (r *Resolver) Ingest(cert *records.OwnershipCertificate, target *records.TargetRecord) error {
	if err := r.InitError(); err != nil {
		return err
	}
	return r.IngestAt(cert, target, r.clockNow())
}

// IngestAt verifies and stores an ownership certificate and target record at an explicit reference time
// without mutating the resolver's configured clock or network profile.
func (r *Resolver) IngestAt(cert *records.OwnershipCertificate, target *records.TargetRecord, now time.Time) error {
	if err := r.InitError(); err != nil {
		return err
	}
	if err := r.verifyPair(cert, target, now); err != nil {
		return err
	}
	return r.commitMonotonic(cert, target)
}

// Resolve resolves a domain through the verified cache and RecordSource fallback.
// Returned records are always deep copies so caller mutations never corrupt cache state.
func (r *Resolver) Resolve(ctx context.Context, domainInput string) (*VerifiedResolution, error) {
	if err := r.InitError(); err != nil {
		return nil, err
	}
	domain, err := names.NormalizeDomain(domainInput, r.profile.TLD)
	if err != nil || domain != strings.ToLower(strings.TrimSpace(domainInput)) {
		return nil, alterrors.New(alterrors.CodeNameNotFound, fmt.Sprintf("domain %q is outside .%s", domainInput, r.profile.TLD))
	}

	now := r.clockNow()

	if r.source == nil {
		if cached, ok := r.getValidCached(domain, now); ok {
			return &cached, nil
		}
		if expErr := r.cachedExpiryError(domain, now); expErr != nil {
			return nil, expErr
		}
		return nil, alterrors.New(alterrors.CodeNameNotFound, "domain not found in verified cache: "+domain)
	}

	ownBytes, tgtBytes, err := r.source.Resolve(ctx, domain)
	if err != nil {
		if alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
			if cached, ok := r.getValidCached(domain, now); ok {
				return &cached, nil
			}
		}
		return nil, err
	}

	cert, err := records.DecodeOwnershipStrict(ownBytes)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "invalid ownership record JSON", err)
	}
	target, err := records.DecodeTargetStrict(tgtBytes)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "invalid target record JSON", err)
	}
	if cert.Domain != domain {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, fmt.Sprintf("ownership record domain %q does not match queried domain %q", cert.Domain, domain))
	}

	if err := r.verifyPair(cert, target, now); err != nil {
		return nil, err
	}
	if err := r.commitMonotonic(cert, target); err != nil {
		return nil, err
	}

	out := VerifiedResolution{
		Ownership: cert.Clone(),
		Target:    target.Clone(),
		FromCache: false,
	}
	return &out, nil
}

func (r *Resolver) clockNow() time.Time {
	r.mu.RLock()
	fn := r.nowFn
	r.mu.RUnlock()
	return fn()
}

func (r *Resolver) verifyPair(cert *records.OwnershipCertificate, target *records.TargetRecord, now time.Time) error {
	if cert == nil || target == nil {
		return alterrors.New(alterrors.CodeRecordUnavailable, "nil ownership or target record")
	}

	fallbackPub := r.fallbackKey

	var ownErr error
	if _, ok := r.profile.AuthorityKey(cert.IssuerKeyID); ok || len(fallbackPub) == 0 {
		ownErr = cert.VerifyForProfile(r.profile, now)
	} else {
		ownErr = cert.VerifyForNetwork(fallbackPub, now, r.profile.NetworkID, r.profile.TLD)
	}
	if ownErr != nil {
		if errors.Is(ownErr, records.ErrRecordExpired) {
			return alterrors.Wrap(alterrors.CodeOwnershipExpired, "ownership certificate has expired", ownErr)
		}
		return alterrors.Wrap(alterrors.CodeRecordUnavailable, "ownership verification failed", ownErr)
	}

	if err := target.Verify(cert, now); err != nil {
		if errors.Is(err, records.ErrRecordExpired) {
			return alterrors.Wrap(alterrors.CodeTargetExpired, "target record has expired", err)
		}
		return alterrors.Wrap(alterrors.CodeRecordUnavailable, "target verification failed", err)
	}
	return nil
}

func (r *Resolver) commitMonotonic(cert *records.OwnershipCertificate, target *records.TargetRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if prev, exists := r.cache[cert.Domain]; exists {
		if cert.Generation < prev.Ownership.Generation {
			return alterrors.New(alterrors.CodeRecordUnavailable, "ownership generation rollback rejected")
		}
		if cert.Generation == prev.Ownership.Generation && target.Sequence < prev.Target.Sequence {
			return alterrors.New(alterrors.CodeRecordUnavailable, "target sequence rollback rejected")
		}
	}

	r.cache[cert.Domain] = VerifiedResolution{
		Ownership: cert.Clone(),
		Target:    target.Clone(),
		FromCache: true,
	}
	return nil
}

func (r *Resolver) getValidCached(domain string, now time.Time) (VerifiedResolution, bool) {
	r.mu.RLock()
	cached, exists := r.cache[domain]
	r.mu.RUnlock()
	if !exists {
		return VerifiedResolution{}, false
	}
	cloned := cached.Clone()
	if err := r.verifyPair(cloned.Ownership, cloned.Target, now); err != nil {
		return VerifiedResolution{}, false
	}
	cloned.FromCache = true
	return cloned, true
}

func (r *Resolver) cachedExpiryError(domain string, now time.Time) error {
	r.mu.RLock()
	cached, exists := r.cache[domain]
	r.mu.RUnlock()
	if !exists {
		return nil
	}
	err := r.verifyPair(cached.Ownership, cached.Target, now)
	if alterrors.IsCode(err, alterrors.CodeOwnershipExpired) || alterrors.IsCode(err, alterrors.CodeTargetExpired) {
		return err
	}
	return nil
}
