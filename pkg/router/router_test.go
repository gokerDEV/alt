package router_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"alt/pkg/config"
	"alt/pkg/router"
)

func boolPtr(b bool) *bool { return &b }

func TestSiteRouterPrefixAndStripRules(t *testing.T) {
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Path", r.URL.Path)
		w.Header().Set("X-Seen-Query", r.URL.RawQuery)
		w.Header().Set("X-Forwarded-Host-Echo", r.Header.Get("X-Forwarded-Host"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("api"))
	}))
	defer apiSrv.Close()

	webSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("web"))
	}))
	defer webSrv.Close()

	site := config.SiteEntry{
		Routes: []config.RouteEntry{
			{
				Match:       "/api/*",
				Upstream:    apiSrv.URL,
				StripPrefix: boolPtr(true),
			},
			{
				Match:    "/*",
				Upstream: webSrv.URL,
			},
		},
	}

	sr, err := router.NewSiteRouter(site, t.TempDir())
	if err != nil {
		t.Fatalf("NewSiteRouter failed: %v", err)
	}

	// 1. /api/users?page=2 matches /api/* and strips /api -> /users
	req1 := httptest.NewRequest(http.MethodGet, "https://myproject.alt/api/users?page=2", nil)
	req1.Header.Set("X-Forwarded-For", "spoofed")
	rec1 := httptest.NewRecorder()
	sr.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || rec1.Body.String() != "api" {
		t.Fatalf("expected api response, got %d %q", rec1.Code, rec1.Body.String())
	}
	if got := rec1.Header().Get("X-Seen-Path"); got != "/users" {
		t.Fatalf("expected stripped path /users, got %q", got)
	}
	if got := rec1.Header().Get("X-Seen-Query"); got != "page=2" {
		t.Fatalf("expected query page=2, got %q", got)
	}
	if got := rec1.Header().Get("X-Forwarded-Host-Echo"); got != "myproject.alt" {
		t.Fatalf("expected X-Forwarded-Host myproject.alt, got %q", got)
	}

	// 2. /api exact matches /api/* and strips /api -> /
	req2 := httptest.NewRequest(http.MethodGet, "https://myproject.alt/api", nil)
	rec2 := httptest.NewRecorder()
	sr.ServeHTTP(rec2, req2)
	if rec2.Body.String() != "api" || rec2.Header().Get("X-Seen-Path") != "/" {
		t.Fatalf("expected /api to strip to '/', got %q", rec2.Header().Get("X-Seen-Path"))
	}

	// 3. /apix does NOT match /api/* (segment boundary enforcement); falls through to /*
	req3 := httptest.NewRequest(http.MethodGet, "https://myproject.alt/apix", nil)
	rec3 := httptest.NewRecorder()
	sr.ServeHTTP(rec3, req3)
	if rec3.Body.String() != "web" || rec3.Header().Get("X-Seen-Path") != "/apix" {
		t.Fatalf("expected /apix to hit web route, got %q (%q)", rec3.Body.String(), rec3.Header().Get("X-Seen-Path"))
	}
}

func TestStaticAndSPAFallback(t *testing.T) {
	tmpDir := t.TempDir()
	distDir := filepath.Join(tmpDir, "dist")
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "index.html"), []byte("<html>SPA</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distDir, "app.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create secret file outside distDir and a symlink inside distDir pointing to it
	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("top-secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(secretFile, filepath.Join(distDir, "escape.txt"))

	site := config.SiteEntry{
		Routes: []config.RouteEntry{
			{
				Match: "/*",
				Static: &config.StaticEntry{
					Dir:         "./dist",
					SPAFallback: true,
				},
			},
		},
	}

	sr, err := router.NewSiteRouter(site, tmpDir)
	if err != nil {
		t.Fatalf("NewSiteRouter failed: %v", err)
	}

	// 1. Existing asset served directly
	reqAsset := httptest.NewRequest(http.MethodGet, "https://static.alt/app.js", nil)
	recAsset := httptest.NewRecorder()
	sr.ServeHTTP(recAsset, reqAsset)
	if recAsset.Code != http.StatusOK || recAsset.Body.String() != "console.log(1)" {
		t.Fatalf("expected app.js content, got %d", recAsset.Code)
	}

	// 2. Dotted SPA route "/user/@goker.alt" with Accept: text/html receives SPA index.html
	reqSPA := httptest.NewRequest(http.MethodGet, "https://static.alt/user/@goker.alt", nil)
	reqSPA.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9")
	reqSPA.Header.Set("Sec-Fetch-Mode", "navigate")
	reqSPA.Header.Set("Sec-Fetch-Dest", "document")
	recSPA := httptest.NewRecorder()
	sr.ServeHTTP(recSPA, reqSPA)
	if recSPA.Code != http.StatusOK || recSPA.Body.String() != "<html>SPA</html>" {
		t.Fatalf("expected SPA fallback for /user/@goker.alt, got %d %q", recSPA.Code, recSPA.Body.String())
	}

	// 3. Missing .js asset never receives SPA fallback even with Accept: text/html
	reqMissingJS := httptest.NewRequest(http.MethodGet, "https://static.alt/missing.js", nil)
	reqMissingJS.Header.Set("Accept", "text/html")
	recMissingJS := httptest.NewRecorder()
	sr.ServeHTTP(recMissingJS, reqMissingJS)
	if recMissingJS.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing .js asset, got %d", recMissingJS.Code)
	}

	// 4. Symlink escaping static root is blocked
	reqEscape := httptest.NewRequest(http.MethodGet, "https://static.alt/escape.txt", nil)
	recEscape := httptest.NewRecorder()
	sr.ServeHTTP(recEscape, reqEscape)
	if recEscape.Code != http.StatusNotFound {
		body, _ := io.ReadAll(recEscape.Result().Body)
		t.Fatalf("expected 404 for symlink escape, got %d (%q)", recEscape.Code, string(body))
	}

	// 5. POST method returns 405 with Allow: GET, HEAD
	reqPost := httptest.NewRequest(http.MethodPost, "https://static.alt/index.html", nil)
	recPost := httptest.NewRecorder()
	sr.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusMethodNotAllowed || recPost.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("expected 405 with Allow: GET, HEAD, got %d (%q)", recPost.Code, recPost.Header().Get("Allow"))
	}
}
