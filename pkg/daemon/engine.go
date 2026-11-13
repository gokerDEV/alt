package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"alt/pkg/config"
	alterrors "alt/pkg/errors"
	"alt/pkg/names"
	"alt/pkg/profile"
	"alt/pkg/records"
	"alt/pkg/resolver"
	"alt/pkg/router"
)

// Options configures optional resolver and origin-proxying behavior for Engine.
type Options struct {
	Profile            *profile.Profile
	Resolver           *resolver.Resolver
	OriginTransport    http.RoundTripper
	AllowLoopbackHTTPS bool // Used only in deterministic local unit/smoke tests
}

// Engine manages local site overrides, monotonic record verification cache,
// IPFS/resolver fallback, and incoming HTTP/HTTPS dispatch for the local ALT daemon.
type Engine struct {
	prof               *profile.Profile
	fallbackKey        ed25519.PublicKey
	resolver           *resolver.Resolver
	originTransport    http.RoundTripper
	allowLoopbackHTTPS bool
	initErr            error

	mu           sync.RWMutex
	localSites   map[string]*router.SiteRouter
	localConfigs map[string]config.SiteEntry
}

// NewEngine initializes a new ALT local routing and resolution engine using the default .alt profile
// and an optional single registry authority key (for backward compatibility).
func NewEngine(authorityPub ed25519.PublicKey) *Engine {
	prof := profile.Default()
	var fbKey ed25519.PublicKey
	if len(authorityPub) == ed25519.PublicKeySize {
		fbKey = append(ed25519.PublicKey(nil), authorityPub...)
	}
	res := resolver.NewWithConfig(resolver.Config{
		Profile:              prof,
		FallbackAuthorityKey: fbKey,
	})
	eng, _ := NewEngineChecked(Options{
		Profile:  prof,
		Resolver: res,
	})
	eng.fallbackKey = fbKey
	return eng
}

// NewEngineChecked initializes an Engine and returns an error if opts.Profile is invalid
// or conflicts with opts.Resolver's bound network profile (networkId, TLD, or trust keys).
func NewEngineChecked(opts Options) (*Engine, error) {
	var prof *profile.Profile
	var res *resolver.Resolver

	if opts.Profile != nil {
		prof = opts.Profile.Clone()
		if err := prof.Validate(); err != nil {
			return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "invalid network profile for engine", err)
		}
	}

	if opts.Resolver != nil {
		res = opts.Resolver
		if err := res.InitError(); err != nil {
			return nil, err
		}
		resProf := res.Profile()
		if resProf == nil {
			return nil, alterrors.New(alterrors.CodeInvalidConfig, "resolver has nil network profile")
		}
		if err := resProf.Validate(); err != nil {
			return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "invalid network profile in resolver", err)
		}
		if prof == nil {
			prof = resProf
		} else if !prof.EqualTrustAndNamespace(resProf) {
			return nil, alterrors.New(
				alterrors.CodeInvalidConfig,
				fmt.Sprintf("engine profile (%s/.%s) disagrees with resolver profile (%s/.%s)",
					prof.NetworkID, prof.TLD, resProf.NetworkID, resProf.TLD),
			)
		}
	} else {
		if prof == nil {
			prof = profile.Default()
		}
		var err error
		res, err = resolver.NewChecked(resolver.Config{Profile: prof})
		if err != nil {
			return nil, err
		}
	}

	res.Seal()

	eng := &Engine{
		prof:               prof,
		fallbackKey:        res.FallbackAuthorityKey(),
		resolver:           res,
		originTransport:    opts.OriginTransport,
		allowLoopbackHTTPS: opts.AllowLoopbackHTTPS,
		localSites:         make(map[string]*router.SiteRouter),
		localConfigs:       make(map[string]config.SiteEntry),
	}
	if eng.originTransport == nil {
		eng.originTransport = eng.defaultSafeOriginTransport()
	}
	return eng, nil
}

// NewEngineWithOptions initializes a new Engine configured with an immutable snapshot of the network profile and resolver.
//
// Deprecated: Use NewEngineChecked instead so profile/resolver configuration errors are returned explicitly at startup.
// If misconfigured, the Engine returned by NewEngineWithOptions fails closed with CodeInvalidConfig on all operations.
func NewEngineWithOptions(opts Options) *Engine {
	eng, err := NewEngineChecked(opts)
	if err == nil {
		return eng
	}
	fallbackProf := profile.Default()
	fallbackRes := resolver.New(fallbackProf, nil)
	fallbackRes.Seal()
	return &Engine{
		prof:               fallbackProf,
		resolver:           fallbackRes,
		initErr:            err,
		localSites:         make(map[string]*router.SiteRouter),
		localConfigs:       make(map[string]config.SiteEntry),
		originTransport:    (&Engine{}).defaultSafeOriginTransport(),
		allowLoopbackHTTPS: opts.AllowLoopbackHTTPS,
	}
}

// Profile returns a cloned copy of the Engine's configured network profile.
func (e *Engine) Profile() *profile.Profile {
	return e.prof.Clone()
}

// ResolveDomain queries the Engine's underlying verified resolver and returns a deep-copied resolution
// without exposing the internal *resolver.Resolver instance.
func (e *Engine) ResolveDomain(ctx context.Context, domain string) (*resolver.VerifiedResolution, error) {
	if e.initErr != nil {
		return nil, e.initErr
	}
	return e.resolver.Resolve(ctx, domain)
}

// InitError returns any configuration mismatch detected during NewEngineWithOptions initialization.
func (e *Engine) InitError() error {
	return e.initErr
}

// UpsertLocalSite compiles and atomically activates a local override for a domain in the configured TLD (§5, §17).
// If compilation or validation fails, any existing active configuration for the domain remains untouched.
func (e *Engine) UpsertLocalSite(domain string, entry config.SiteEntry, baseDir string) error {
	if e.initErr != nil {
		return e.initErr
	}
	normDomain, err := names.NormalizeDomain(domain, e.prof.TLD)
	if err != nil || normDomain != strings.ToLower(strings.TrimSpace(domain)) {
		return alterrors.New(alterrors.CodeInvalidConfig, fmt.Sprintf("domain %q is not valid in .%s", domain, e.prof.TLD))
	}

	sr, err := router.NewSiteRouter(entry, baseDir)
	if err != nil {
		return err
	}

	e.mu.Lock()
	e.localSites[normDomain] = sr
	e.localConfigs[normDomain] = entry
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

// ListLocalSites returns the list of active local override domains.
func (e *Engine) ListLocalSites() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.localSites))
	for d := range e.localSites {
		out = append(out, d)
	}
	return out
}

// IngestSignedRecords verifies an ownership certificate and target record against the network profile
// and enforces monotonic generation/sequence anti-rollback rules (§8, §17) without mutating shared trust state.
func (e *Engine) IngestSignedRecords(cert *records.OwnershipCertificate, target *records.TargetRecord, now time.Time) error {
	if e.initErr != nil {
		return e.initErr
	}
	if cert == nil || target == nil {
		return alterrors.New(alterrors.CodeRecordUnavailable, "nil record")
	}

	var verifyErr error
	if _, ok := e.prof.AuthorityKey(cert.IssuerKeyID); ok || len(e.fallbackKey) == 0 {
		verifyErr = cert.VerifyForProfile(e.prof, now)
	} else {
		verifyErr = cert.VerifyForNetwork(e.fallbackKey, now, e.prof.NetworkID, e.prof.TLD)
	}
	if verifyErr != nil {
		return verifyErr
	}
	if err := target.Verify(cert, now); err != nil {
		return err
	}

	return e.resolver.IngestAt(cert, target, now)
}

// ServeHTTP dispatches incoming requests: local overrides always take precedence over network records (§5).
func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.initErr != nil {
		writeALTError(w, e.initErr)
		return
	}
	host := stripHostPort(r.Host)

	if !names.IsDomain(host, e.prof.TLD) {
		writeALTError(w, alterrors.New(alterrors.CodeNameNotFound, fmt.Sprintf("host %q is outside .%s", host, e.prof.TLD)))
		return
	}

	e.mu.RLock()
	localRouter, hasLocal := e.localSites[host]
	e.mu.RUnlock()

	if hasLocal {
		w.Header().Set("X-Alt-Resolution", "local-override")
		localRouter.ServeHTTP(w, r)
		return
	}

	resolved, err := e.resolver.Resolve(r.Context(), host)
	if err != nil {
		writeALTError(w, err)
		return
	}

	switch resolved.Target.Mode {
	case records.TargetModeHTTPS:
		e.serveHTTPSTarget(w, r, host, resolved)
	case records.TargetModeP2P:
		writeALTError(w, alterrors.New(alterrors.CodePublisherOffline, "P2P signaling orchestration is not active in this slice"))
	default:
		writeALTError(w, alterrors.New(alterrors.CodeRecordUnavailable, "unsupported target mode"))
	}
}

func (e *Engine) serveHTTPSTarget(w http.ResponseWriter, r *http.Request, altHost string, resolved *resolver.VerifiedResolution) {
	targetURL, err := url.Parse(resolved.Target.Target)
	if err != nil || targetURL.Scheme != "https" || targetURL.Host == "" || targetURL.User != nil {
		writeALTError(w, alterrors.New(alterrors.CodeRecordUnavailable, "invalid HTTPS target origin"))
		return
	}

	originHostname := targetURL.Hostname()
	if !e.allowLoopbackHTTPS && IsDisallowedOriginHost(originHostname) {
		writeALTError(w, alterrors.New(alterrors.CodeDirectConnectFailed, "HTTPS target points to a disallowed private, loopback, or special-use address"))
		return
	}

	w.Header().Set("X-Alt-Resolution", "verified-record")
	w.Header().Set("X-Alt-Network", e.prof.NetworkID)

	proxy := &httputil.ReverseProxy{
		Transport: e.originTransport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = targetURL.Host
			basePath := strings.TrimRight(targetURL.Path, "/")
			if basePath != "" {
				pr.Out.URL.Path = basePath + pr.In.URL.Path
				pr.Out.URL.RawPath = ""
			} else {
				pr.Out.URL.Path = pr.In.URL.Path
				pr.Out.URL.RawPath = pr.In.URL.RawPath
			}
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			// Use origin's real hostname for SNI and HTTP Host verification (ARCHITECTURE.md §8)
			pr.Out.Host = targetURL.Host

			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Set("X-Alt-Domain", altHost)
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
			if strings.Contains(strings.ToLower(proxyErr.Error()), "x509:") || strings.Contains(strings.ToLower(proxyErr.Error()), "tls:") {
				writeALTError(rw, alterrors.Wrap(alterrors.CodeOriginTLSError, "upstream TLS verification failed", proxyErr))
				return
			}
			writeALTError(rw, alterrors.Wrap(alterrors.CodeDirectConnectFailed, "failed to reach verified HTTPS target", proxyErr))
		},
	}
	proxy.ServeHTTP(w, r)
}

func (e *Engine) defaultSafeOriginTransport() *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			if e.allowLoopbackHTTPS {
				return nil
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid dial address %q: %w", address, err)
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("unparsed IP address %q: %w", host, err)
			}
			if IsDisallowedOriginAddr(addr) {
				return fmt.Errorf("refusing socket connection to non-public/special-use IP %s", addr.String())
			}
			return nil
		},
	}
	return &http.Transport{
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if !e.allowLoopbackHTTPS && IsDisallowedOriginHost(host) {
				return nil, fmt.Errorf("refusing connection to disallowed host %s", host)
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP addresses resolved for %s", host)
			}
			var publicAddrs []netip.Addr
			for _, ipAddr := range ips {
				parsed, ok := netip.AddrFromSlice(ipAddr.IP)
				if !ok {
					return nil, fmt.Errorf("invalid resolved IP for %s", host)
				}
				parsed = parsed.Unmap()
				if !e.allowLoopbackHTTPS && IsDisallowedOriginAddr(parsed) {
					return nil, fmt.Errorf("refusing connection to non-public/special-use IP %s", parsed.String())
				}
				publicAddrs = append(publicAddrs, parsed)
			}
			// Dial the verified global unicast IP directly to prevent DNS rebinding (ARCHITECTURE.md §8)
			var lastErr error
			for _, candidate := range publicAddrs {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
}

// specialUsePrefixes covers IANA IPv4 and IPv6 Special-Purpose Address Registries
// (RFC 6890, RFC 6598 CGNAT, RFC 5737 TEST-NET, RFC 2544 benchmarking, NAT64, 6to4, Teredo, documentation, etc.)
// so that only globally routable public unicast addresses are permitted for HTTPS origins.
var specialUsePrefixes = mustParsePrefixes(
	// IPv4 special-purpose ranges
	"0.0.0.0/8",          // "This network" (RFC 1122)
	"10.0.0.0/8",         // Private-Use (RFC 1918)
	"100.64.0.0/10",      // Shared Address Space / CGNAT (RFC 6598)
	"127.0.0.0/8",        // Loopback (RFC 1122)
	"169.254.0.0/16",     // Link-Local / Cloud Metadata (RFC 3927)
	"172.16.0.0/12",      // Private-Use (RFC 1918)
	"192.0.0.0/24",       // IETF Protocol Assignments (RFC 6890)
	"192.0.2.0/24",       // TEST-NET-1 Documentation (RFC 5737)
	"192.88.99.0/24",     // 6to4 Relay Anycast (RFC 7526)
	"192.168.0.0/16",     // Private-Use (RFC 1918)
	"198.18.0.0/15",      // Benchmarking (RFC 2544)
	"198.51.100.0/24",    // TEST-NET-2 Documentation (RFC 5737)
	"203.0.113.0/24",     // TEST-NET-3 Documentation (RFC 5737)
	"224.0.0.0/4",        // Multicast (RFC 5771)
	"240.0.0.0/4",        // Reserved for Future Use + Limited Broadcast 255.255.255.255/32 (RFC 1112)
	"255.255.255.255/32", // Limited Broadcast

	// IPv6 special-purpose ranges
	"::/128",         // Unspecified (RFC 4291)
	"::1/128",        // Loopback (RFC 4291)
	"::ffff:0:0/96",  // IPv4-mapped (handled via Unmap, kept as defense-in-depth)
	"64:ff9b::/96",   // IPv4-IPv6 Translation Well-Known Prefix (RFC 6052)
	"64:ff9b:1::/48", // IPv4-IPv6 Translation Local-Use (RFC 8215)
	"100::/64",       // Discard-Only Prefix (RFC 6666)
	"2001::/23",      // IETF Protocol Assignments, incl. Teredo 2001::/32 & Benchmarking 2001:2::/48
	"2001:db8::/32",  // Documentation (RFC 3849)
	"2002::/16",      // 6to4 (RFC 3056) — embeds arbitrary IPv4 in bits 16..47
	"fc00::/7",       // Unique-Local (RFC 4193)
	"fe80::/10",      // Link-Local Unicast (RFC 4291)
	"fec0::/10",      // Site-Local deprecated (RFC 3879)
	"ff00::/8",       // Multicast (RFC 4291)
)

func mustParsePrefixes(cidrs ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

// IsDisallowedOriginHost checks whether a hostname or IP literal is a special-use/local name
// or resolves to a non-public/special-use IP literal.
func IsDisallowedOriginHost(host string) bool {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if lower == "" {
		return true
	}
	for _, reservedSuffix := range []string{
		"localhost",
		"local",
		"internal",
		"intranet",
		"home.arpa",
		"invalid",
		"example",
		"test",
		"onion",
	} {
		if lower == reservedSuffix || strings.HasSuffix(lower, "."+reservedSuffix) {
			return true
		}
	}

	if addr, err := netip.ParseAddr(lower); err == nil {
		return IsDisallowedOriginAddr(addr)
	}
	if ip := net.ParseIP(lower); ip != nil {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			return IsDisallowedOriginAddr(addr)
		}
		return true
	}
	return false
}

// IsDisallowedOriginAddr returns true unless addr (after unmapping IPv4-in-IPv6 and checking embedded
// IPv4 transition addresses) is a globally routable public unicast IP outside all IANA special-purpose blocks.
func IsDisallowedOriginAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	// Reject IPv6 zone identifiers (e.g., fe80::1%lo0)
	if addr.Zone() != "" {
		return true
	}

	unmapped := addr.Unmap()
	if !unmapped.IsGlobalUnicast() ||
		unmapped.IsLoopback() ||
		unmapped.IsPrivate() ||
		unmapped.IsLinkLocalUnicast() ||
		unmapped.IsLinkLocalMulticast() ||
		unmapped.IsMulticast() ||
		unmapped.IsUnspecified() {
		return true
	}

	// Inspect IPv4-compatible IPv6 addresses (::w.x.y.z/96) which Unmap() does not unwrap
	if unmapped.Is6() {
		b := unmapped.As16()
		isCompatV4 := true
		for i := 0; i < 12; i++ {
			if b[i] != 0 {
				isCompatV4 = false
				break
			}
		}
		if isCompatV4 {
			return true
		}
	}

	for _, prefix := range specialUsePrefixes {
		if prefix.Contains(unmapped) {
			return true
		}
	}
	return false
}

func stripHostPort(hostport string) string {
	h := strings.ToLower(strings.TrimSpace(hostport))
	if strings.HasPrefix(h, "[") {
		if host, _, err := net.SplitHostPort(h); err == nil {
			return host
		}
		return h
	}
	for i := 0; i < len(h); i++ {
		if h[i] == ':' {
			return h[:i]
		}
	}
	return h
}

func writeALTError(w http.ResponseWriter, err error) {
	status := http.StatusBadGateway
	switch {
	case alterrors.IsCode(err, alterrors.CodeNameNotFound):
		status = http.StatusNotFound
	case alterrors.IsCode(err, alterrors.CodeOwnershipExpired), alterrors.IsCode(err, alterrors.CodeTargetExpired):
		status = http.StatusGone
	case alterrors.IsCode(err, alterrors.CodeRecordUnavailable),
		alterrors.IsCode(err, alterrors.CodePublisherOffline),
		alterrors.IsCode(err, alterrors.CodeSignalingUnavailable):
		status = http.StatusServiceUnavailable
	case alterrors.IsCode(err, alterrors.CodeDirectConnectFailed),
		alterrors.IsCode(err, alterrors.CodeOriginTLSError):
		status = http.StatusBadGateway
	case alterrors.IsCode(err, alterrors.CodeInvalidConfig):
		status = http.StatusInternalServerError
	}
	if ae, ok := err.(*alterrors.Error); ok {
		w.Header().Set("X-Alt-Error-Code", string(ae.Code))
	}
	http.Error(w, err.Error(), status)
}
