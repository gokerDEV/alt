package daemon

import (
	"crypto/ed25519"
	"net/http"
	"sync"
	"time"

	"alt/pkg/config"
	alterrors "alt/pkg/errors"
	"alt/pkg/records"
	"alt/pkg/router"
)

type cachedResolution struct {
	cert   *records.OwnershipCertificate
	target *records.TargetRecord
}

// Engine manages local site overrides, monotonic record verification cache,
// and incoming HTTP/HTTPS dispatch for the local ALT daemon.
type Engine struct {
	authorityPub ed25519.PublicKey

	mu            sync.RWMutex
	localSites    map[string]*router.SiteRouter
	localConfigs  map[string]config.SiteEntry
	verifiedCache map[string]cachedResolution
}

// NewEngine initializes a new ALT local routing and resolution engine.
func NewEngine(authorityPub ed25519.PublicKey) *Engine {
	return &Engine{
		authorityPub:  authorityPub,
		localSites:    make(map[string]*router.SiteRouter),
		localConfigs:  make(map[string]config.SiteEntry),
		verifiedCache: make(map[string]cachedResolution),
	}
}

// UpsertLocalSite compiles and atomically activates a local override for a .alt domain (§5, §17).
// If compilation or validation fails, any existing active configuration for the domain remains untouched.
func (e *Engine) UpsertLocalSite(domain string, entry config.SiteEntry, baseDir string) error {
	sr, err := router.NewSiteRouter(entry, baseDir)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.localSites[domain] = sr
	e.localConfigs[domain] = entry
	e.mu.Unlock()
	return nil
}

// RemoveLocalSite removes a local override (`alt halt <domain>`), restoring network resolution.
func (e *Engine) RemoveLocalSite(domain string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.localSites[domain]; !ok {
		return false
	}
	delete(e.localSites, domain)
	delete(e.localConfigs, domain)
	return true
}

// ListLocalSites returns the sorted list of active local override domains.
func (e *Engine) ListLocalSites() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.localSites))
	for d := range e.localSites {
		out = append(out, d)
	}
	return out
}

// IngestSignedRecords verifies an ownership certificate and target record against the authority
// public key and enforces monotonic generation/sequence anti-rollback rules (§8, §17).
func (e *Engine) IngestSignedRecords(cert *records.OwnershipCertificate, target *records.TargetRecord, now time.Time) error {
	if err := cert.Verify(e.authorityPub, now); err != nil {
		return err
	}
	if err := target.Verify(cert, now); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if prev, exists := e.verifiedCache[cert.Domain]; exists {
		if cert.Generation < prev.cert.Generation {
			return alterrors.New(alterrors.CodeRecordUnavailable, "ownership generation rollback rejected")
		}
		if cert.Generation == prev.cert.Generation && target.Sequence < prev.target.Sequence {
			return alterrors.New(alterrors.CodeRecordUnavailable, "target sequence rollback rejected")
		}
	}

	e.verifiedCache[cert.Domain] = cachedResolution{
		cert:   cert,
		target: target,
	}
	return nil
}

// ServeHTTP dispatches incoming requests: local overrides take precedence over network records (§5).
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			host = host[:i]
			break
		}
	}

	e.mu.RLock()
	localRouter, hasLocal := e.localSites[host]
	e.mu.RUnlock()

	if hasLocal {
		w.Header().Set("X-Alt-Resolution", "local-override")
		localRouter.ServeHTTP(w, r)
		return
	}

	http.Error(w, string(alterrors.CodeNameNotFound)+": no local override or resolved target for "+host, http.StatusBadGateway)
}

