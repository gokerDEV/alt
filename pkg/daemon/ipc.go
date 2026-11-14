package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"alt/pkg/config"
	alterrors "alt/pkg/errors"
	"alt/pkg/names"
	"alt/pkg/resolver"
)

const (
	maxIPCBodyBytes = 1 << 20 // 1 MiB
)

// IPCErrorResponse is returned as JSON whenever an IPC request fails.
type IPCErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// IPCStatusResponse reports live daemon, proxy, DNS stub, CA, local override, and resolver state.
type IPCStatusResponse struct {
	Status        string                  `json:"status"`
	PID           int                     `json:"pid"`
	StartedAt     string                  `json:"startedAt"`
	UptimeSeconds int64                   `json:"uptimeSeconds"`
	Version       string                  `json:"version"`
	NetworkID     string                  `json:"networkId"`
	TLD           string                  `json:"tld"`
	HTTPSAddr     string                  `json:"httpsAddr"`
	DNSAddr       string                  `json:"dnsAddr,omitempty"`
	LoopbackIP    string                  `json:"loopbackIp,omitempty"`
	CACertPath    string                  `json:"caCertPath,omitempty"`
	SocketPath    string                  `json:"socketPath"`
	StateDir      string                  `json:"stateDir"`
	LogFilePath   string                  `json:"logFilePath,omitempty"`
	Sites         []PersistedSiteOverride `json:"sites"`
	ConfigFiles   []string                `json:"configFiles,omitempty"`
	Resolver      resolver.CacheStats     `json:"resolver"`
}

// IPCDevUpsertRequest configures one or more local site overrides in the running daemon and persists them.
type IPCDevUpsertRequest struct {
	Overrides  []PersistedSiteOverride `json:"overrides"`
	ConfigFile string                  `json:"configFile,omitempty"`
}

// IPCDevUpsertResponse confirms the activated local overrides.
type IPCDevUpsertResponse struct {
	Activated []PersistedSiteOverride `json:"activated"`
	HTTPSAddr string                  `json:"httpsAddr"`
}

// IPCHaltRequest removes a single local domain override or all local overrides.
type IPCHaltRequest struct {
	Domain string `json:"domain,omitempty"`
	All    bool   `json:"all,omitempty"`
}

// IPCHaltResponse reports which overrides were removed.
type IPCHaltResponse struct {
	Removed int      `json:"removed"`
	Domains []string `json:"domains,omitempty"`
}

// IPCListResponse returns all active local site overrides from the daemon.
type IPCListResponse struct {
	NetworkID string                  `json:"networkId"`
	TLD       string                  `json:"tld"`
	HTTPSAddr string                  `json:"httpsAddr"`
	Sites     []PersistedSiteOverride `json:"sites"`
}

// IPCReloadResponse reports the result of reloading tracked `alt.yaml` files and optional profile overrides.
type IPCReloadResponse struct {
	ReloadedConfigs []string `json:"reloadedConfigs"`
	ActiveSites     int      `json:"activeSites"`
}

// IPCResolveResponse returns a verified network or local resolution from the running daemon.
type IPCResolveResponse struct {
	Domain     string                       `json:"domain"`
	Mode       string                       `json:"mode"` // "local-override" or "verified-record"
	LocalSite  *PersistedSiteOverride       `json:"localSite,omitempty"`
	Resolution *resolver.VerifiedResolution `json:"resolution,omitempty"`
}

// IPCServerConfig configures the local Unix domain socket IPC server for a running daemon.
type IPCServerConfig struct {
	Engine      *Engine
	StateStore  *DaemonStateStore
	StateDir    string
	SocketPath  string
	StartedAt   time.Time
	Version     string
	HTTPSAddr   string
	DNSAddr     string
	LoopbackIP  string
	CACertPath  string
	LogFilePath string
	ShutdownFn  func()
}

// IPCServer serves the authenticated local Unix socket control API for the ALT daemon.
type IPCServer struct {
	cfg      IPCServerConfig
	listener net.Listener
	server   *http.Server
	mu       sync.Mutex
}

// RestoreSitesIntoEngine loads all persisted site overrides from store into engine at daemon startup.
func RestoreSitesIntoEngine(engine *Engine, store *DaemonStateStore) error {
	if engine == nil || store == nil {
		return nil
	}
	for _, ov := range store.List() {
		baseDir := ov.BaseDir
		if strings.TrimSpace(baseDir) == "" {
			baseDir = "."
		}
		if err := engine.UpsertLocalSite(ov.Domain, ov.Entry, baseDir); err != nil {
			return fmt.Errorf("restore persisted override for %s: %w", ov.Domain, err)
		}
	}
	return nil
}

// StartIPCServer binds the Unix domain socket (`0600` permissions inside a `0700` parent directory),
// cleans up any stale socket left by an ungraceful crash (after the caller holds `InstanceLock`),
// and serves IPC requests until `Close()` is called.
func StartIPCServer(cfg IPCServerConfig) (*IPCServer, error) {
	if cfg.Engine == nil {
		return nil, errors.New("daemon: IPCServer requires non-nil Engine")
	}
	sockPath := strings.TrimSpace(cfg.SocketPath)
	if sockPath == "" {
		var err error
		sockPath, err = ResolveSocketPath(cfg.StateDir)
		if err != nil {
			return nil, err
		}
		cfg.SocketPath = sockPath
	}

	if err := ensureSecureDir(filepath.Dir(sockPath)); err != nil {
		return nil, err
	}
	// Remove stale socket file if present (caller holds exclusive InstanceLock).
	if st, err := os.Lstat(sockPath); err == nil {
		if st.Mode().IsRegular() {
			return nil, fmt.Errorf("daemon: refusing to overwrite regular file at socket path %s", sockPath)
		}
		_ = os.Remove(sockPath)
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("daemon: listen unix socket %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return nil, fmt.Errorf("daemon: chmod unix socket %s: %w", sockPath, err)
	}

	if cfg.StartedAt.IsZero() {
		cfg.StartedAt = time.Now().UTC()
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}

	s := &IPCServer{
		cfg:      cfg,
		listener: ln,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", s.handleHealth)
	mux.HandleFunc("/v1/status", s.handleStatus)
	mux.HandleFunc("/v1/sites", s.handleSites)
	mux.HandleFunc("/v1/dev", s.handleDevUpsert)
	mux.HandleFunc("/v1/halt", s.handleHalt)
	mux.HandleFunc("/v1/reload", s.handleReload)
	mux.HandleFunc("/v1/resolve", s.handleResolve)
	mux.HandleFunc("/v1/shutdown", s.handleShutdown)

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		_ = s.server.Serve(ln)
	}()

	return s, nil
}

// SocketPath returns the active Unix domain socket path.
func (s *IPCServer) SocketPath() string {
	if s == nil {
		return ""
	}
	return s.cfg.SocketPath
}

// Close gracefully stops the IPC server and removes the Unix socket file.
func (s *IPCServer) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := s.server.Shutdown(ctx)
	_ = s.listener.Close()
	_ = os.Remove(s.cfg.SocketPath)
	s.server = nil
	return err
}

func (s *IPCServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected GET")
		return
	}
	writeIPCJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"pid":    os.Getpid(),
	})
}

func (s *IPCServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected GET")
		return
	}
	prof := s.cfg.Engine.Profile()
	var netID, tld string
	if prof != nil {
		netID = prof.NetworkID
		tld = prof.TLD
	}
	sites := s.currentSites()
	var cfgFiles []string
	if s.cfg.StateStore != nil {
		cfgFiles = s.cfg.StateStore.ConfigFiles()
	}

	uptime := int64(time.Since(s.cfg.StartedAt).Seconds())
	if uptime < 0 {
		uptime = 0
	}

	resp := IPCStatusResponse{
		Status:        "running",
		PID:           os.Getpid(),
		StartedAt:     s.cfg.StartedAt.UTC().Format(time.RFC3339),
		UptimeSeconds: uptime,
		Version:       s.cfg.Version,
		NetworkID:     netID,
		TLD:           tld,
		HTTPSAddr:     s.cfg.HTTPSAddr,
		DNSAddr:       s.cfg.DNSAddr,
		LoopbackIP:    s.cfg.LoopbackIP,
		CACertPath:    s.cfg.CACertPath,
		SocketPath:    s.cfg.SocketPath,
		StateDir:      s.cfg.StateDir,
		LogFilePath:   s.cfg.LogFilePath,
		Sites:         sites,
		ConfigFiles:   cfgFiles,
		Resolver:      s.cfg.Engine.ResolverStats(),
	}
	writeIPCJSON(w, http.StatusOK, resp)
}

func (s *IPCServer) handleSites(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected GET")
		return
	}
	prof := s.cfg.Engine.Profile()
	var netID, tld string
	if prof != nil {
		netID = prof.NetworkID
		tld = prof.TLD
	}
	writeIPCJSON(w, http.StatusOK, IPCListResponse{
		NetworkID: netID,
		TLD:       tld,
		HTTPSAddr: s.cfg.HTTPSAddr,
		Sites:     s.currentSites(),
	})
}

func (s *IPCServer) handleDevUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected POST")
		return
	}
	var req IPCDevUpsertRequest
	if err := decodeIPCJSON(r.Body, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
		return
	}
	if len(req.Overrides) == 0 {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), "at least one site override is required")
		return
	}

	prof := s.cfg.Engine.Profile()
	tld := "alt"
	if prof != nil {
		tld = prof.TLD
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	normalized := make([]PersistedSiteOverride, 0, len(req.Overrides))
	for _, ov := range req.Overrides {
		normDomain, err := names.NormalizeDomain(ov.Domain, tld)
		if err != nil {
			writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
			return
		}
		baseDir := strings.TrimSpace(ov.BaseDir)
		if baseDir == "" {
			baseDir = "."
		}
		absBase, err := filepath.Abs(baseDir)
		if err != nil {
			writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
			return
		}
		if err := s.cfg.Engine.UpsertLocalSite(normDomain, ov.Entry, absBase); err != nil {
			writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
			return
		}
		ovCopy := ov
		ovCopy.Domain = normDomain
		ovCopy.BaseDir = absBase
		ovCopy.UpdatedAt = nowStr
		normalized = append(normalized, ovCopy)
	}

	if s.cfg.StateStore != nil {
		if err := s.cfg.StateStore.Upsert(normalized, req.ConfigFile); err != nil {
			writeIPCError(w, http.StatusInternalServerError, string(alterrors.CodeInvalidConfig), err.Error())
			return
		}
	}

	writeIPCJSON(w, http.StatusOK, IPCDevUpsertResponse{
		Activated: normalized,
		HTTPSAddr: s.cfg.HTTPSAddr,
	})
}

func (s *IPCServer) handleHalt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected POST")
		return
	}
	var req IPCHaltRequest
	if err := decodeIPCJSON(r.Body, &req); err != nil {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
		return
	}

	if req.All {
		domains := s.cfg.Engine.ListLocalSites()
		sort.Strings(domains)
		n := s.cfg.Engine.RemoveAllLocalSites()
		if s.cfg.StateStore != nil {
			if err := s.cfg.StateStore.Clear(); err != nil {
				writeIPCError(w, http.StatusInternalServerError, string(alterrors.CodeInvalidConfig), err.Error())
				return
			}
		}
		writeIPCJSON(w, http.StatusOK, IPCHaltResponse{
			Removed: n,
			Domains: domains,
		})
		return
	}

	prof := s.cfg.Engine.Profile()
	tld := "alt"
	if prof != nil {
		tld = prof.TLD
	}
	normDomain, err := names.NormalizeDomain(req.Domain, tld)
	if err != nil {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
		return
	}

	removedEngine := s.cfg.Engine.RemoveLocalSite(normDomain)
	var removedStore bool
	if s.cfg.StateStore != nil {
		removedStore, err = s.cfg.StateStore.Remove(normDomain)
		if err != nil {
			writeIPCError(w, http.StatusInternalServerError, string(alterrors.CodeInvalidConfig), err.Error())
			return
		}
	}

	if !removedEngine && !removedStore {
		writeIPCJSON(w, http.StatusOK, IPCHaltResponse{
			Removed: 0,
		})
		return
	}
	writeIPCJSON(w, http.StatusOK, IPCHaltResponse{
		Removed: 1,
		Domains: []string{normDomain},
	})
}

// ReloadTrackedConfigs reloads all `alt.yaml` files tracked in StateStore and updates the Engine atomically.
func (s *IPCServer) ReloadTrackedConfigs() (*IPCReloadResponse, error) {
	if s == nil {
		return &IPCReloadResponse{}, nil
	}
	prof := s.cfg.Engine.Profile()
	tld := "alt"
	if prof != nil {
		tld = prof.TLD
	}

	var cfgFiles []string
	if s.cfg.StateStore != nil {
		cfgFiles = s.cfg.StateStore.ConfigFiles()
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	var reloaded []string
	for _, cfgPath := range cfgFiles {
		loaded, err := config.LoadFileForTLD(cfgPath, tld)
		if err != nil {
			return nil, fmt.Errorf("reload %s: %w", cfgPath, err)
		}
		baseDir := filepath.Dir(cfgPath)
		var batch []PersistedSiteOverride
		for domain, entry := range loaded.Sites {
			if err := s.cfg.Engine.UpsertLocalSite(domain, entry, baseDir); err != nil {
				return nil, fmt.Errorf("reload site %s from %s: %w", domain, cfgPath, err)
			}
			batch = append(batch, PersistedSiteOverride{
				Domain:     domain,
				SourceMode: "config",
				BaseDir:    baseDir,
				ConfigFile: cfgPath,
				Entry:      entry,
				UpdatedAt:  nowStr,
			})
		}
		if s.cfg.StateStore != nil && len(batch) > 0 {
			if err := s.cfg.StateStore.Upsert(batch, cfgPath); err != nil {
				return nil, err
			}
		}
		reloaded = append(reloaded, cfgPath)
	}

	return &IPCReloadResponse{
		ReloadedConfigs: reloaded,
		ActiveSites:     len(s.cfg.Engine.ListLocalSites()),
	}, nil
}

func (s *IPCServer) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected POST")
		return
	}
	resp, err := s.ReloadTrackedConfigs()
	if err != nil {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), err.Error())
		return
	}
	writeIPCJSON(w, http.StatusOK, resp)
}

func (s *IPCServer) handleResolve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected GET")
		return
	}
	qDomain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if qDomain == "" {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeInvalidConfig), "missing domain query parameter")
		return
	}
	prof := s.cfg.Engine.Profile()
	tld := "alt"
	if prof != nil {
		tld = prof.TLD
	}
	normDomain, err := names.NormalizeDomain(qDomain, tld)
	if err != nil {
		writeIPCError(w, http.StatusBadRequest, string(alterrors.CodeNameNotFound), err.Error())
		return
	}

	for _, st := range s.currentSites() {
		if st.Domain == normDomain {
			stCopy := st
			writeIPCJSON(w, http.StatusOK, IPCResolveResponse{
				Domain:    normDomain,
				Mode:      "local-override",
				LocalSite: &stCopy,
			})
			return
		}
	}

	res, err := s.cfg.Engine.ResolveDomain(r.Context(), normDomain)
	if err != nil {
		code := string(alterrors.CodeRecordUnavailable)
		if ae, ok := err.(*alterrors.Error); ok {
			code = string(ae.Code)
		}
		writeIPCError(w, http.StatusBadGateway, code, err.Error())
		return
	}
	writeIPCJSON(w, http.StatusOK, IPCResolveResponse{
		Domain:     normDomain,
		Mode:       "verified-record",
		Resolution: res,
	})
}

func (s *IPCServer) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeIPCError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "expected POST")
		return
	}
	writeIPCJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
	if s.cfg.ShutdownFn != nil {
		go func() {
			time.Sleep(25 * time.Millisecond)
			s.cfg.ShutdownFn()
		}()
	}
}

func (s *IPCServer) currentSites() []PersistedSiteOverride {
	if s.cfg.StateStore != nil {
		return s.cfg.StateStore.List()
	}
	details := s.cfg.Engine.ListLocalSiteDetails()
	out := make([]PersistedSiteOverride, 0, len(details))
	for _, d := range details {
		out = append(out, PersistedSiteOverride{
			Domain:     d.Domain,
			SourceMode: "memory",
			BaseDir:    d.BaseDir,
			Entry:      d.Entry,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Domain < out[j].Domain
	})
	return out
}

func decodeIPCJSON(r io.Reader, dst any) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxIPCBodyBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxIPCBodyBytes {
		return errors.New("IPC request payload exceeds maximum size")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing tokens in IPC JSON payload")
	}
	return nil
}

func writeIPCJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeIPCError(w http.ResponseWriter, status int, code, msg string) {
	writeIPCJSON(w, status, IPCErrorResponse{
		Error: msg,
		Code:  code,
	})
}

// IPCClient communicates with a running ALT daemon over its Unix domain socket.
type IPCClient struct {
	socketPath string
	httpClient *http.Client
}

// NewIPCClient constructs a client for the daemon Unix socket inside `stateDir` (or an explicit socket path).
func NewIPCClient(stateDirOrSocket string) (*IPCClient, error) {
	trimmed := strings.TrimSpace(stateDirOrSocket)
	if trimmed == "" {
		return nil, errors.New("daemon: empty stateDir for IPCClient")
	}
	sockPath := trimmed
	if !strings.HasSuffix(sockPath, ".sock") {
		var err error
		sockPath, err = ResolveSocketPath(trimmed)
		if err != nil {
			return nil, err
		}
	}

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", sockPath)
		},
	}
	return &IPCClient{
		socketPath: sockPath,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		},
	}, nil
}

// SocketPath returns the resolved Unix socket path used by this client.
func (c *IPCClient) SocketPath() string {
	if c == nil {
		return ""
	}
	return c.socketPath
}

// Health checks whether the daemon is responsive over IPC.
func (c *IPCClient) Health(ctx context.Context) error {
	var out map[string]any
	return c.doJSON(ctx, http.MethodGet, "/v1/health", nil, &out)
}

// Status fetches the running daemon's comprehensive status snapshot.
func (c *IPCClient) Status(ctx context.Context) (*IPCStatusResponse, error) {
	var out IPCStatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/status", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListSites fetches all active local overrides from the running daemon.
func (c *IPCClient) ListSites(ctx context.Context) (*IPCListResponse, error) {
	var out IPCListResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/sites", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DevUpsert activates and persists one or more local site overrides in the running daemon.
func (c *IPCClient) DevUpsert(ctx context.Context, req IPCDevUpsertRequest) (*IPCDevUpsertResponse, error) {
	var out IPCDevUpsertResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/dev", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Halt removes a single local domain override or all local overrides in the running daemon.
func (c *IPCClient) Halt(ctx context.Context, req IPCHaltRequest) (*IPCHaltResponse, error) {
	var out IPCHaltResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/halt", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Reload instructs the daemon to reload all tracked `alt.yaml` configuration files.
func (c *IPCClient) Reload(ctx context.Context) (*IPCReloadResponse, error) {
	var out IPCReloadResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/reload", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Resolve queries the running daemon's resolver or local override table for `domain`.
func (c *IPCClient) Resolve(ctx context.Context, domain string) (*IPCResolveResponse, error) {
	var out IPCResolveResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/resolve?domain="+domain, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Shutdown requests a clean graceful shutdown of the running daemon.
func (c *IPCClient) Shutdown(ctx context.Context) error {
	var out map[string]any
	return c.doJSON(ctx, http.MethodPost, "/v1/shutdown", map[string]any{}, &out)
}

func (c *IPCClient) doJSON(ctx context.Context, method, path string, reqBody any, respDst any) error {
	if c == nil || c.httpClient == nil {
		return errors.New("daemon: uninitialized IPCClient")
	}
	var bodyReader io.Reader
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://alt-daemon"+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxIPCBodyBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errEnv IPCErrorResponse
		if json.Unmarshal(raw, &errEnv) == nil && errEnv.Error != "" {
			if errEnv.Code != "" {
				return fmt.Errorf("[%s] %s", errEnv.Code, errEnv.Error)
			}
			return errors.New(errEnv.Error)
		}
		return fmt.Errorf("daemon IPC HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if respDst != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, respDst); err != nil {
			return fmt.Errorf("decode daemon IPC response: %w", err)
		}
	}
	return nil
}
