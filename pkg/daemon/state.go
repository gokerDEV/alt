package daemon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"alt/pkg/config"
	alterrors "alt/pkg/errors"
	"alt/pkg/names"
)

const (
	// SchemaDaemonStateV1 identifies the versioned persistent daemon override state schema.
	SchemaDaemonStateV1 = "alt.daemon-state.v1"

	maxDaemonStateBytes = 2 << 20
)

// PersistedSiteOverride stores a local development override or alt.yaml site binding in daemon-state.json.
type PersistedSiteOverride struct {
	Domain     string           `json:"domain"`
	SourceMode string           `json:"sourceMode"` // "port", "dir", "routes", or "config"
	BaseDir    string           `json:"baseDir"`
	ConfigFile string           `json:"configFile,omitempty"`
	Entry      config.SiteEntry `json:"entry"`
	UpdatedAt  string           `json:"updatedAt"`
}

type daemonStateDocument struct {
	Schema      string                           `json:"schema"`
	Version     int                              `json:"version"`
	NetworkID   string                           `json:"networkId"`
	TLD         string                           `json:"tld"`
	UpdatedAt   string                           `json:"updatedAt"`
	ConfigFiles []string                         `json:"configFiles,omitempty"`
	Sites       map[string]PersistedSiteOverride `json:"sites"`
}

// DaemonStateStore persists local site overrides and linked `alt.yaml` files across daemon restarts.
type DaemonStateStore struct {
	path      string
	networkID string
	tld       string

	mu  sync.Mutex
	doc daemonStateDocument
}

// OpenDaemonStateStore opens or initializes `<path>` (`0600` regular file) for `networkID` and `tld`.
func OpenDaemonStateStore(path, networkID, tld string) (*DaemonStateStore, error) {
	absPath, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "resolve daemon state path", err)
	}
	normTLD, err := names.NormalizeTLD(tld)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "normalize daemon state TLD", err)
	}
	netID := strings.TrimSpace(networkID)
	if netID == "" {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "daemon state networkId must not be empty")
	}

	if err := os.MkdirAll(filepath.Dir(absPath), 0o700); err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "create daemon state directory", err)
	}

	s := &DaemonStateStore{
		path:      absPath,
		networkID: netID,
		tld:       normTLD,
		doc: daemonStateDocument{
			Schema:    SchemaDaemonStateV1,
			Version:   1,
			NetworkID: netID,
			TLD:       normTLD,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Sites:     make(map[string]PersistedSiteOverride),
		},
	}

	st, err := os.Lstat(absPath)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "stat daemon state file", err)
	}
	if !st.Mode().IsRegular() {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "daemon state file must be a regular file")
	}
	if st.Size() > maxDaemonStateBytes {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "daemon state file exceeds maximum byte limit")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, alterrors.New(
			alterrors.CodeInvalidConfig,
			fmt.Sprintf("daemon state file %s has insecure permissions %04o (expected 0600)", absPath, st.Mode().Perm()),
		)
	}

	raw, err := os.ReadFile(absPath)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "read daemon state file", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var loaded daemonStateDocument
	if err := dec.Decode(&loaded); err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "corrupt daemon state JSON", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, alterrors.New(alterrors.CodeInvalidConfig, "trailing tokens in daemon state JSON")
	}
	if loaded.Schema != SchemaDaemonStateV1 || loaded.Version != 1 {
		return nil, alterrors.New(
			alterrors.CodeInvalidConfig,
			fmt.Sprintf("unsupported daemon state schema %q (version %d)", loaded.Schema, loaded.Version),
		)
	}
	if loaded.NetworkID != netID || loaded.TLD != normTLD {
		return nil, alterrors.New(
			alterrors.CodeInvalidConfig,
			fmt.Sprintf("daemon state (%s/.%s) disagrees with configured (%s/.%s)", loaded.NetworkID, loaded.TLD, netID, normTLD),
		)
	}
	if loaded.Sites == nil {
		loaded.Sites = make(map[string]PersistedSiteOverride)
	}
	s.doc = loaded
	return s, nil
}

// Path returns the absolute file path of daemon-state.json.
func (s *DaemonStateStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// List returns deterministic, sorted copies of all persisted site overrides.
func (s *DaemonStateStore) List() []PersistedSiteOverride {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PersistedSiteOverride, 0, len(s.doc.Sites))
	for _, v := range s.doc.Sites {
		cp := v
		cp.Entry = cloneSiteEntry(v.Entry)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Domain < out[j].Domain
	})
	return out
}

// ConfigFiles returns a copy of tracked `alt.yaml` paths for reload (`SIGHUP` / `POST /v1/reload`).
func (s *DaemonStateStore) ConfigFiles() []string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.doc.ConfigFiles...)
}

// Upsert saves one or more site overrides atomically.
func (s *DaemonStateStore) Upsert(overrides []PersistedSiteOverride, configFile string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cloneDocLocked()
	nowStr := time.Now().UTC().Format(time.RFC3339)
	next.UpdatedAt = nowStr

	for _, ov := range overrides {
		normDomain, err := names.NormalizeDomain(ov.Domain, s.tld)
		if err != nil {
			return alterrors.Wrap(alterrors.CodeInvalidConfig, "invalid domain for daemon state", err)
		}
		ovCopy := ov
		ovCopy.Domain = normDomain
		ovCopy.Entry = cloneSiteEntry(ov.Entry)
		if ovCopy.UpdatedAt == "" {
			ovCopy.UpdatedAt = nowStr
		}
		next.Sites[normDomain] = ovCopy
	}

	if trimmedCfg := strings.TrimSpace(configFile); trimmedCfg != "" {
		absCfg, err := filepath.Abs(trimmedCfg)
		if err == nil {
			found := false
			for _, existing := range next.ConfigFiles {
				if existing == absCfg {
					found = true
					break
				}
			}
			if !found {
				next.ConfigFiles = append(next.ConfigFiles, absCfg)
			}
		}
	}

	if err := writeDaemonJSONAtomic(s.path, next); err != nil {
		return err
	}
	s.doc = next
	return nil
}

// Remove deletes a single domain override (and cleans up unreferenced configFile entries).
func (s *DaemonStateStore) Remove(domain string) (bool, error) {
	if s == nil {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.doc.Sites[domain]; !exists {
		return false, nil
	}
	next := s.cloneDocLocked()
	delete(next.Sites, domain)
	next.ConfigFiles = activeConfigFiles(next.Sites)
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := writeDaemonJSONAtomic(s.path, next); err != nil {
		return false, err
	}
	s.doc = next
	return true, nil
}

// Clear removes all persisted local overrides and tracked config files.
func (s *DaemonStateStore) Clear() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	next := s.cloneDocLocked()
	next.Sites = make(map[string]PersistedSiteOverride)
	next.ConfigFiles = nil
	next.UpdatedAt = time.Now().UTC().Format(time.RFC3339)

	if err := writeDaemonJSONAtomic(s.path, next); err != nil {
		return err
	}
	s.doc = next
	return nil
}

func activeConfigFiles(sites map[string]PersistedSiteOverride) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, st := range sites {
		if st.ConfigFile != "" {
			if _, ok := seen[st.ConfigFile]; !ok {
				seen[st.ConfigFile] = struct{}{}
				out = append(out, st.ConfigFile)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *DaemonStateStore) cloneDocLocked() daemonStateDocument {
	cp := daemonStateDocument{
		Schema:      s.doc.Schema,
		Version:     s.doc.Version,
		NetworkID:   s.doc.NetworkID,
		TLD:         s.doc.TLD,
		UpdatedAt:   s.doc.UpdatedAt,
		ConfigFiles: append([]string(nil), s.doc.ConfigFiles...),
		Sites:       make(map[string]PersistedSiteOverride, len(s.doc.Sites)),
	}
	for k, v := range s.doc.Sites {
		vCopy := v
		vCopy.Entry = cloneSiteEntry(v.Entry)
		cp.Sites[k] = vCopy
	}
	return cp
}

func writeDaemonJSONAtomic(targetPath string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".daemon-state-*.tmp")
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
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}
