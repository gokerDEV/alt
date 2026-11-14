package profile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// SchemaProfileBundleV1 identifies an authority-signed trust-root / profile rotation bundle.
	SchemaProfileBundleV1 = "alt.profile-bundle.v1"
)

// SignedProfileBundle allows an existing trusted authority key to sign a monotonic profile/trust-root
// rotation update (e.g., adding a rotated registry key, updating the IPNS root or bootstrap CID,
// or updating default gateways) without requiring a new binary release.
type SignedProfileBundle struct {
	Schema      string  `json:"schema"`
	NetworkID   string  `json:"networkId"`
	Sequence    uint64  `json:"sequence"`
	IssuedAt    string  `json:"issuedAt"`
	ExpiresAt   string  `json:"expiresAt"`
	SignerKeyID string  `json:"signerKeyId"`
	Profile     Profile `json:"profile"`
	Signature   string  `json:"signature"`
}

type canonicalProfileBundle struct {
	Schema      string  `json:"schema"`
	NetworkID   string  `json:"networkId"`
	Sequence    uint64  `json:"sequence"`
	IssuedAt    string  `json:"issuedAt"`
	ExpiresAt   string  `json:"expiresAt"`
	SignerKeyID string  `json:"signerKeyId"`
	Profile     Profile `json:"profile"`
}

// SigningBytes returns the domain-separated canonical byte representation of SignedProfileBundle.
func (b *SignedProfileBundle) SigningBytes() ([]byte, error) {
	if b == nil {
		return nil, errors.New("profile: nil SignedProfileBundle")
	}
	if strings.TrimSpace(b.NetworkID) == "" || b.Profile.NetworkID != b.NetworkID {
		return nil, errors.New("profile: bundle networkId must match embedded profile.networkId")
	}
	if b.Sequence == 0 {
		return nil, errors.New("profile: bundle sequence must be >= 1")
	}
	payload, err := json.Marshal(canonicalProfileBundle{
		Schema:      b.Schema,
		NetworkID:   b.NetworkID,
		Sequence:    b.Sequence,
		IssuedAt:    b.IssuedAt,
		ExpiresAt:   b.ExpiresAt,
		SignerKeyID: b.SignerKeyID,
		Profile:     b.Profile,
	})
	if err != nil {
		return nil, err
	}
	prefix := SchemaProfileBundleV1 + "\x00" + b.NetworkID + "\x00"
	return append([]byte(prefix), payload...), nil
}

// Sign signs the bundle using an existing authority Ed25519 private key.
func (b *SignedProfileBundle) Sign(priv ed25519.PrivateKey) error {
	if b.Schema == "" {
		b.Schema = SchemaProfileBundleV1
	}
	if b.NetworkID == "" {
		b.NetworkID = b.Profile.NetworkID
	}
	msg, err := b.SigningBytes()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, msg)
	b.Signature = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks the SignedProfileBundle against `currentTrustedProfile` at `now` and returns
// the validated replacement Profile if the signature, validity window, and schema are valid.
func (b *SignedProfileBundle) Verify(currentTrustedProfile *Profile, now time.Time) (*Profile, error) {
	if b == nil {
		return nil, errors.New("profile: nil bundle")
	}
	if b.Schema != SchemaProfileBundleV1 {
		return nil, fmt.Errorf("profile: unsupported bundle schema %q", b.Schema)
	}
	if currentTrustedProfile == nil {
		return nil, errors.New("profile: nil currentTrustedProfile")
	}
	if b.NetworkID != currentTrustedProfile.NetworkID || b.Profile.NetworkID != currentTrustedProfile.NetworkID {
		return nil, fmt.Errorf("profile: bundle networkId %q disagrees with trusted networkId %q", b.NetworkID, currentTrustedProfile.NetworkID)
	}
	if b.Profile.TLD != currentTrustedProfile.TLD {
		return nil, fmt.Errorf("profile: bundle TLD %q disagrees with trusted TLD %q", b.Profile.TLD, currentTrustedProfile.TLD)
	}

	signerPub, ok := currentTrustedProfile.AuthorityKey(b.SignerKeyID)
	if !ok {
		return nil, fmt.Errorf("profile: unknown signerKeyId %q in current trust store", b.SignerKeyID)
	}

	issuedAt, err := time.Parse(time.RFC3339, b.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("profile: invalid bundle issuedAt: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, b.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("profile: invalid bundle expiresAt: %w", err)
	}
	if !expiresAt.After(issuedAt) {
		return nil, errors.New("profile: bundle expiresAt must be after issuedAt")
	}
	if issuedAt.After(now.Add(5 * time.Minute)) {
		return nil, errors.New("profile: bundle issuedAt is in the future")
	}
	if !now.Before(expiresAt) {
		return nil, errors.New("profile: bundle has expired")
	}

	msg, err := b.SigningBytes()
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(b.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(signerPub, msg, sig) {
		return nil, errors.New("profile: bundle signature verification failed")
	}

	nextProf := b.Profile.Clone()
	if err := nextProf.Validate(); err != nil {
		return nil, err
	}
	return nextProf, nil
}

// DecodeSignedBundleStrict parses a SignedProfileBundle JSON document strictly.
func DecodeSignedBundleStrict(raw []byte) (*SignedProfileBundle, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b SignedProfileBundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("profile: malformed bundle JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("profile: trailing data after bundle JSON")
	}
	return &b, nil
}

// PinnedProfilePath returns `<stateDir>/profile.yaml` for a network state directory.
func PinnedProfilePath(stateDir string) string {
	return filepath.Join(stateDir, "profile.yaml")
}

// ProfileBundleMeta records the highest verified bundle sequence persisted in `stateDir`
// so stale signed profile bundles can never downgrade a rotated trust root.
type ProfileBundleMeta struct {
	Schema      string `json:"schema"`
	NetworkID   string `json:"networkId"`
	Sequence    uint64 `json:"sequence"`
	SignerKeyID string `json:"signerKeyId"`
	UpdatedAt   string `json:"updatedAt"`
}

// BundleMetaPath returns `<stateDir>/profile-bundle.meta.json`.
func BundleMetaPath(stateDir string) string {
	return filepath.Join(stateDir, "profile-bundle.meta.json")
}

// LoadBundleMeta loads `<stateDir>/profile-bundle.meta.json` if present.
func LoadBundleMeta(stateDir string) (*ProfileBundleMeta, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, os.ErrNotExist
	}
	raw, err := os.ReadFile(BundleMetaPath(stateDir))
	if err != nil {
		return nil, err
	}
	var m ProfileBundleMeta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ApplySignedBundleToStateDir verifies `bundle` against `currentTrustedProfile` at `now`,
// enforces strictly increasing bundle `Sequence` against `<stateDir>/profile-bundle.meta.json`,
// and atomically persists both the updated `profile.yaml` and sequence watermark.
func ApplySignedBundleToStateDir(stateDir string, currentTrustedProfile *Profile, bundle *SignedProfileBundle, now time.Time) (*Profile, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, errors.New("profile: stateDir is required")
	}
	nextProf, err := bundle.Verify(currentTrustedProfile, now)
	if err != nil {
		return nil, err
	}
	if prevMeta, err := LoadBundleMeta(stateDir); err == nil && prevMeta != nil {
		if prevMeta.NetworkID == bundle.NetworkID && bundle.Sequence <= prevMeta.Sequence {
			return nil, fmt.Errorf("profile: bundle sequence %d does not advance persisted sequence %d (rollback rejected)", bundle.Sequence, prevMeta.Sequence)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("profile: read bundle metadata: %w", err)
	}

	if err := SavePinnedProfile(stateDir, nextProf); err != nil {
		return nil, err
	}
	meta := ProfileBundleMeta{
		Schema:      SchemaProfileBundleV1,
		NetworkID:   bundle.NetworkID,
		Sequence:    bundle.Sequence,
		SignerKeyID: bundle.SignerKeyID,
		UpdatedAt:   now.UTC().Format(time.RFC3339),
	}
	metaRaw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	metaRaw = append(metaRaw, '\n')
	metaPath := BundleMetaPath(stateDir)
	metaTmp := metaPath + ".tmp"
	if err := os.WriteFile(metaTmp, metaRaw, 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(metaTmp, metaPath); err != nil {
		return nil, err
	}
	return nextProf, nil
}

// SavePinnedProfile writes a validated Profile atomically to `<stateDir>/profile.yaml` (`0600`).
func SavePinnedProfile(stateDir string, p *Profile) error {
	if p == nil {
		return errors.New("profile: nil Profile")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	raw, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	target := PinnedProfilePath(stateDir)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

// LoadPinnedOrOfficial loads `<stateDir>/profile.yaml` if present, otherwise returns `Official()`.
func LoadPinnedOrOfficial(stateDir string) (*Profile, error) {
	if strings.TrimSpace(stateDir) != "" {
		pPath := PinnedProfilePath(stateDir)
		if _, err := os.Stat(pPath); err == nil {
			return LoadFile(pPath)
		}
	}
	return Official(), nil
}
