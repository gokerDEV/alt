package resolver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	alterrors "alt/pkg/errors"
	"alt/pkg/records"
)

const (
	// SchemaResolverStateV1 identifies the versioned on-disk monotonic anti-rollback state file.
	SchemaResolverStateV1 = "alt.resolver-state.v1"

	// maxStateFileBytes bounds the size of persisted resolver state loaded from disk (4 MiB).
	maxStateFileBytes = 4 << 20
)

// PersistedIPNSState records the highest verified IPNS sequence and content-addressed manifest
// for a specific k51... IPNS root so daemon restarts never accept rolled-back IPNS pointers.
type PersistedIPNSState struct {
	IPNSRoot        string `json:"ipnsRoot"`
	HighestSequence uint64 `json:"highestSequence"`
	TargetCID       string `json:"targetCid"`
	ExpiresAt       string `json:"expiresAt"`
	RawManifest     []byte `json:"rawManifest,omitempty"`
	UpdatedAt       string `json:"updatedAt"`
}

// PersistedDomainEntry records the highest verified (generation, sequence) and signed record pair
// for a single domain in a network namespace.
type PersistedDomainEntry struct {
	Generation uint64                        `json:"generation"`
	Sequence   uint64                        `json:"sequence"`
	Ownership  *records.OwnershipCertificate `json:"ownership"`
	Target     *records.TargetRecord         `json:"target"`
	UpdatedAt  string                        `json:"updatedAt"`
}

// resolverStateDocument is the versioned JSON envelope written atomically to disk.
type resolverStateDocument struct {
	Schema    string                          `json:"schema"`
	Version   int                             `json:"version"`
	NetworkID string                          `json:"networkId"`
	UpdatedAt string                          `json:"updatedAt"`
	IPNS      *PersistedIPNSState             `json:"ipns,omitempty"`
	Domains   map[string]PersistedDomainEntry `json:"domains"`
}

// StateStore provides atomic, network-isolated disk persistence for verified domain records
// and IPNS sequence watermarks. All writes use 0600 temp-file + fsync + atomic rename inside a 0700 directory.
type StateStore struct {
	path      string
	networkID string

	mu  sync.Mutex
	doc resolverStateDocument
}

// OpenStateStore opens or initializes a network-scoped verified resolver state file on disk.
// If the file already exists, its schema, version, permissions, and networkId are strictly validated.
func OpenStateStore(path, networkID string) (*StateStore, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "resolver state path must not be empty")
	}
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "resolve state file path", err)
	}
	netID := strings.TrimSpace(networkID)
	if netID == "" {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "resolver state networkId must not be empty")
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "create resolver state directory", err)
	}

	s := &StateStore{
		path:      absPath,
		networkID: netID,
		doc: resolverStateDocument{
			Schema:    SchemaResolverStateV1,
			Version:   1,
			NetworkID: netID,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Domains:   make(map[string]PersistedDomainEntry),
		},
	}

	st, err := os.Lstat(absPath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "stat resolver state file", err)
	}
	if !st.Mode().IsRegular() {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "resolver state file must be a regular file")
	}
	if st.Size() > maxStateFileBytes {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "resolver state file exceeds maximum byte limit")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, alterrors.New(
			alterrors.CodeInvalidConfig,
			fmt.Sprintf("resolver state file %s has insecure permissions %04o (expected 0600)", absPath, st.Mode().Perm()),
		)
	}

	raw, err := os.ReadFile(absPath)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "read resolver state file", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var loaded resolverStateDocument
	if err := dec.Decode(&loaded); err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "corrupt resolver state JSON", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "trailing tokens in resolver state JSON")
	}
	if loaded.Schema != SchemaResolverStateV1 || loaded.Version != 1 {
		return nil, alterrors.New(
			alterrors.CodeInvalidConfig,
			fmt.Sprintf("unsupported resolver state schema %q (version %d)", loaded.Schema, loaded.Version),
		)
	}
	if loaded.NetworkID != netID {
		return nil, alterrors.New(
			alterrors.CodeInvalidConfig,
			fmt.Sprintf("resolver state networkId %q disagrees with configured networkId %q", loaded.NetworkID, netID),
		)
	}
	if loaded.Domains == nil {
		loaded.Domains = make(map[string]PersistedDomainEntry)
	}
	s.doc = loaded
	return s, nil
}

// Path returns the absolute file path of the state store.
func (s *StateStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// SnapshotDomains returns deep copies of all persisted domain entries.
func (s *StateStore) SnapshotDomains() map[string]PersistedDomainEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]PersistedDomainEntry, len(s.doc.Domains))
	for k, v := range s.doc.Domains {
		out[k] = PersistedDomainEntry{
			Generation: v.Generation,
			Sequence:   v.Sequence,
			Ownership:  v.Ownership.Clone(),
			Target:     v.Target.Clone(),
			UpdatedAt:  v.UpdatedAt,
		}
	}
	return out
}

// SnapshotIPNS returns a deep copy of the persisted IPNS monotonic state, if any.
func (s *StateStore) SnapshotIPNS() *PersistedIPNSState {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.doc.IPNS == nil {
		return nil
	}
	cp := *s.doc.IPNS
	if len(s.doc.IPNS.RawManifest) > 0 {
		cp.RawManifest = append([]byte(nil), s.doc.IPNS.RawManifest...)
	}
	return &cp
}

// SaveDomain atomically records a verified domain entry if it meets or advances the persisted monotonic floor.
func (s *StateStore) SaveDomain(cert *records.OwnershipCertificate, target *records.TargetRecord, now time.Time) error {
	if s == nil {
		return nil
	}
	if cert == nil || target == nil {
		return alterrors.New(alterrors.CodeRecordUnavailable, "nil record cannot be persisted")
	}
	if cert.NetworkID != s.networkID || target.NetworkID != s.networkID {
		return alterrors.New(alterrors.CodeRecordUnavailable, "record networkId does not match state store networkId")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if prev, exists := s.doc.Domains[cert.Domain]; exists {
		if cert.Generation < prev.Generation {
			return alterrors.New(alterrors.CodeRecordUnavailable, "persisted ownership generation rollback rejected")
		}
		if cert.Generation == prev.Generation && target.Sequence < prev.Sequence {
			return alterrors.New(alterrors.CodeRecordUnavailable, "persisted target sequence rollback rejected")
		}
	}

	ts := now.UTC().Format(time.RFC3339)
	nextDoc := s.cloneDocLocked()
	nextDoc.UpdatedAt = ts
	nextDoc.Domains[cert.Domain] = PersistedDomainEntry{
		Generation: cert.Generation,
		Sequence:   target.Sequence,
		Ownership:  cert.Clone(),
		Target:     target.Clone(),
		UpdatedAt:  ts,
	}

	if err := writeJSONFileAtomic(s.path, nextDoc); err != nil {
		return alterrors.Wrap(alterrors.CodeRecordUnavailable, "persist verified resolver state", err)
	}
	s.doc = nextDoc
	return nil
}

// SaveIPNS atomically records the highest verified IPNS sequence and manifest snapshot for ipnsRoot.
func (s *StateStore) SaveIPNS(ipnsRoot string, rec *VerifiedIPNSRecord, rawManifest []byte, now time.Time) error {
	if s == nil {
		return nil
	}
	if rec == nil || strings.TrimSpace(ipnsRoot) == "" {
		return alterrors.New(alterrors.CodeRecordUnavailable, "invalid IPNS state")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.doc.IPNS != nil && s.doc.IPNS.IPNSRoot == ipnsRoot {
		if rec.Sequence < s.doc.IPNS.HighestSequence {
			return alterrors.New(alterrors.CodeRecordUnavailable, "persisted IPNS sequence rollback rejected")
		}
	}

	ts := now.UTC().Format(time.RFC3339)
	nextDoc := s.cloneDocLocked()
	nextDoc.UpdatedAt = ts
	nextDoc.IPNS = &PersistedIPNSState{
		IPNSRoot:        ipnsRoot,
		HighestSequence: rec.Sequence,
		TargetCID:       rec.TargetCID,
		ExpiresAt:       rec.ExpiresAt.UTC().Format(time.RFC3339Nano),
		RawManifest:     append([]byte(nil), rawManifest...),
		UpdatedAt:       ts,
	}

	if err := writeJSONFileAtomic(s.path, nextDoc); err != nil {
		return alterrors.Wrap(alterrors.CodeRecordUnavailable, "persist verified IPNS state", err)
	}
	s.doc = nextDoc
	return nil
}

func (s *StateStore) cloneDocLocked() resolverStateDocument {
	cp := resolverStateDocument{
		Schema:    s.doc.Schema,
		Version:   s.doc.Version,
		NetworkID: s.doc.NetworkID,
		UpdatedAt: s.doc.UpdatedAt,
		Domains:   make(map[string]PersistedDomainEntry, len(s.doc.Domains)),
	}
	if s.doc.IPNS != nil {
		ipnsCopy := *s.doc.IPNS
		if len(s.doc.IPNS.RawManifest) > 0 {
			ipnsCopy.RawManifest = append([]byte(nil), s.doc.IPNS.RawManifest...)
		}
		cp.IPNS = &ipnsCopy
	}
	for k, v := range s.doc.Domains {
		cp.Domains[k] = PersistedDomainEntry{
			Generation: v.Generation,
			Sequence:   v.Sequence,
			Ownership:  v.Ownership.Clone(),
			Target:     v.Target.Clone(),
			UpdatedAt:  v.UpdatedAt,
		}
	}
	return cp
}

func writeJSONFileAtomic(targetPath string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	f, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, targetPath); err != nil {
		return err
	}
	cleanup = false

	// Best-effort directory fsync for crash durability.
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}
