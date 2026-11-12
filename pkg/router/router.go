package router

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"alt/pkg/config"
)

type compiledRoute struct {
	entry      config.RouteEntry
	isWildcard bool
	prefix     string // For "/api/*", prefix is "/api". For "/*", prefix is "/".
	handler    http.Handler
}

// SiteRouter routes incoming HTTP requests for a single .alt site according to §18 rules.
type SiteRouter struct {
	exactRoutes    map[string]compiledRoute
	wildcardRoutes []compiledRoute // Sorted by descending prefix length
	rootWildcard   *compiledRoute
}

// NewSiteRouter compiles a validated config.SiteEntry into an executable http.Handler.
// baseDir is used to resolve relative static directory paths.
func NewSiteRouter(site config.SiteEntry, baseDir string) (*SiteRouter, error) {
	if err := site.ValidateRoutes(); err != nil {
		return nil, err
	}

	sr := &SiteRouter{
		exactRoutes: make(map[string]compiledRoute),
	}

	for _, r := range site.Routes {
		h, err := buildRouteHandler(r, baseDir)
		if err != nil {
			return nil, err
		}

		if r.Match == "/*" {
			cr := compiledRoute{
				entry:      r,
				isWildcard: true,
				prefix:     "/",
				handler:    h,
			}
			sr.rootWildcard = &cr
		} else if strings.HasSuffix(r.Match, "/*") {
			prefix := strings.TrimSuffix(r.Match, "/*")
			sr.wildcardRoutes = append(sr.wildcardRoutes, compiledRoute{
				entry:      r,
				isWildcard: true,
				prefix:     prefix,
				handler:    h,
			})
		} else {
			sr.exactRoutes[r.Match] = compiledRoute{
				entry:      r,
				isWildcard: false,
				prefix:     r.Match,
				handler:    h,
			}
		}
	}

	sort.Slice(sr.wildcardRoutes, func(i, j int) bool {
		return len(sr.wildcardRoutes[i].prefix) > len(sr.wildcardRoutes[j].prefix)
	})

	return sr, nil
}

func (sr *SiteRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath, ok := sanitizeRequestPath(r.URL.Path, r.URL.RawPath)
	if !ok {
		http.Error(w, "Bad Request: ambiguous or invalid path", http.StatusBadRequest)
		return
	}

	// 1. Exact match first
	if cr, exists := sr.exactRoutes[reqPath]; exists {
		cr.handler.ServeHTTP(w, r)
		return
	}

	// 2. Longest segment-boundary prefix match
	for _, cr := range sr.wildcardRoutes {
		if matchesSegmentPrefix(reqPath, cr.prefix) {
			cr.handler.ServeHTTP(w, r)
			return
		}
	}

	// 3. Fallback root wildcard "/*"
	if sr.rootWildcard != nil {
		sr.rootWildcard.handler.ServeHTTP(w, r)
		return
	}

	http.NotFound(w, r)
}

func matchesSegmentPrefix(reqPath, prefix string) bool {
	if reqPath == prefix {
		return true
	}
	return strings.HasPrefix(reqPath, prefix+"/")
}

// sanitizeRequestPath rejects encoded path separators (%2f, %5c), backslashes, and dot-segments.
func sanitizeRequestPath(urlPath, rawPath string) (string, bool) {
	if urlPath == "" || !strings.HasPrefix(urlPath, "/") {
		return "", false
	}
	if strings.Contains(urlPath, "\\") {
		return "", false
	}
	if rawPath != "" {
		lowerRaw := strings.ToLower(rawPath)
		if strings.Contains(lowerRaw, "%2f") || strings.Contains(lowerRaw, "%5c") {
			return "", false
		}
		if strings.Contains(rawPath, "\\") {
			return "", false
		}
	}

	segments := strings.Split(urlPath, "/")
	for _, seg := range segments {
		if seg == "." || seg == ".." {
			return "", false
		}
	}
	return urlPath, true
}

func buildRouteHandler(r config.RouteEntry, baseDir string) (http.Handler, error) {
	if r.Upstream != "" {
		return buildUpstreamProxy(r)
	}
	if r.Static != nil {
		return buildStaticHandler(r, baseDir)
	}
	return nil, fmt.Errorf("router: route %q has neither upstream nor static configuration", r.Match)
}

func buildUpstreamProxy(r config.RouteEntry) (http.Handler, error) {
	targetURL, err := url.Parse(r.Upstream)
	if err != nil {
		return nil, err
	}

	prefixToStrip := ""
	if r.ShouldStripPrefix() && strings.HasSuffix(r.Match, "/*") && r.Match != "/*" {
		prefixToStrip = strings.TrimSuffix(r.Match, "/*")
	}

	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			// Pin "localhost" to loopback IP so DNS never leaves loopback (§18)
			if strings.EqualFold(host, "localhost") {
				addr = net.JoinHostPort("127.0.0.1", port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			reqPath := pr.In.URL.Path
			if prefixToStrip != "" {
				stripped := strings.TrimPrefix(reqPath, prefixToStrip)
				if stripped == "" {
					stripped = "/"
				}
				pr.Out.URL.Path = stripped
				pr.Out.URL.RawPath = ""
			} else {
				pr.Out.URL.Path = reqPath
				pr.Out.URL.RawPath = pr.In.URL.RawPath
			}

			pr.Out.URL.Scheme = targetURL.Scheme
			pr.Out.URL.Host = targetURL.Host
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery

			// Strip client-supplied forwarding headers before regenerating (§18)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")

			pr.SetXForwarded()
			if pr.In.Host != "" {
				pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
			}
			if pr.In.TLS != nil {
				pr.Out.Header.Set("X-Forwarded-Proto", "https")
			} else {
				pr.Out.Header.Set("X-Forwarded-Proto", "http")
			}
		},
	}

	return proxy, nil
}

// nonFallbackExtensions lists asset file extensions that must never receive SPA index.html fallback (§18).
var nonFallbackExtensions = map[string]bool{
	".js":    true,
	".mjs":   true,
	".css":   true,
	".map":   true,
	".json":  true,
	".wasm":  true,
	".png":   true,
	".jpg":   true,
	".jpeg":  true,
	".gif":   true,
	".svg":   true,
	".webp":  true,
	".avif":  true,
	".ico":   true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".otf":   true,
	".eot":   true,
}

func buildStaticHandler(r config.RouteEntry, baseDir string) (http.Handler, error) {
	dir := r.Static.Dir
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(baseDir, dir)
	}
	absRoot, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	mountPrefix := ""
	if strings.HasSuffix(r.Match, "/*") && r.Match != "/*" {
		mountPrefix = strings.TrimSuffix(r.Match, "/*")
	} else if r.Match != "/" && r.Match != "/*" {
		mountPrefix = r.Match
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		relPath := req.URL.Path
		if mountPrefix != "" {
			relPath = strings.TrimPrefix(relPath, mountPrefix)
			if relPath == "" {
				relPath = "/"
			}
		}

		if served := tryServeSafeFile(w, req, absRoot, relPath); served {
			return
		}

		if r.Static.SPAFallback && eligibleForSPAFallback(req, relPath) {
			if served := tryServeSafeFile(w, req, absRoot, "/index.html"); served {
				return
			}
		}

		http.NotFound(w, req)
	}), nil
}

func tryServeSafeFile(w http.ResponseWriter, req *http.Request, absRoot, relURLPath string) bool {
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return false
	}

	cleaned := filepath.FromSlash(path.Clean("/" + relURLPath))
	candidate := filepath.Join(realRoot, cleaned)

	info, err := os.Stat(candidate)
	if err != nil {
		return false
	}
	if info.IsDir() {
		indexCandidate := filepath.Join(candidate, "index.html")
		indexInfo, err := os.Stat(indexCandidate)
		if err != nil || indexInfo.IsDir() {
			return false
		}
		candidate = indexCandidate
		info = indexInfo
	}

	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false
	}

	// Enforce root containment after symlink evaluation
	if resolved != realRoot && !strings.HasPrefix(resolved, realRoot+string(filepath.Separator)) {
		return false
	}

	f, err := os.Open(resolved)
	if err != nil {
		return false
	}
	defer f.Close()

	http.ServeContent(w, req, info.Name(), info.ModTime(), f)
	return true
}

func eligibleForSPAFallback(req *http.Request, relPath string) bool {
	lastSeg := path.Base(relPath)
	ext := strings.ToLower(path.Ext(lastSeg))
	if nonFallbackExtensions[ext] {
		return false
	}

	if mode := req.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return false
	}
	if dest := req.Header.Get("Sec-Fetch-Dest"); dest != "" &&
		dest != "document" && dest != "iframe" && dest != "frame" {
		return false
	}

	return acceptsHTML(req.Header.Get("Accept"))
}

// acceptsHTML checks whether the Accept header explicitly accepts text/html with q > 0.
func acceptsHTML(acceptHeader string) bool {
	if acceptHeader == "" {
		return false
	}
	parts := strings.Split(acceptHeader, ",")
	for _, part := range parts {
		segments := strings.Split(strings.TrimSpace(part), ";")
		mediaType := strings.ToLower(strings.TrimSpace(segments[0]))
		if mediaType != "text/html" && mediaType != "application/xhtml+xml" {
			continue
		}
		q := 1.0
		for _, param := range segments[1:] {
			kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
			if len(kv) == 2 && strings.ToLower(strings.TrimSpace(kv[0])) == "q" {
				parsed, err := strconv.ParseFloat(strings.TrimSpace(kv[1]), 64)
				if err != nil {
					q = 0
				} else {
					q = parsed
				}
			}
		}
		if q > 0 {
			return true
		}
	}
	return false
}

