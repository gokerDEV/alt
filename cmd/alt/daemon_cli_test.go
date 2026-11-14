package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"alt/pkg/profile"
	"alt/pkg/records"
	"alt/pkg/resolver"
	"gopkg.in/yaml.v3"
)

var stdoutCaptureMu sync.Mutex

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	stdoutCaptureMu.Lock()
	defer stdoutCaptureMu.Unlock()

	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		close(done)
	}()

	runErr := fn()
	_ = w.Close()
	os.Stdout = origStdout
	<-done
	_ = r.Close()
	return buf.String(), runErr
}

func TestCLIDaemonDevListHaltReloadDoctorAndFallback(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "state")

	// 1. Prepare a signed IPFS fixture for `goker.alt` so halting local override falls back to verified record resolution
	authPub, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC().Add(-1 * time.Minute)
	exp := now.Add(24 * time.Hour)

	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      "alt-test-v1",
		Domain:         "goker.alt",
		AccountID:      "acct_goker",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      exp.Format(time.RFC3339),
		IssuerKeyID:    "test-auth-1",
	}
	_ = cert.Sign(authPriv)

	target := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           "alt-test-v1",
		Domain:              "goker.alt",
		OwnershipGeneration: 1,
		Sequence:            1,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://127.0.0.1:9443", // Verified record hits SSRF guard -> proves signed resolution ran
		IssuedAt:            now.Format(time.RFC3339),
		ExpiresAt:           exp.Format(time.RFC3339),
	}
	_ = target.Sign(ownerPriv)

	ownRaw, _ := json.Marshal(cert)
	tgtRaw, _ := json.Marshal(target)
	manifestBytes, _ := json.Marshal(resolver.Manifest{
		Schema:    resolver.SchemaManifestV1,
		NetworkID: "alt-test-v1",
		Records: map[string]resolver.ManifestEntry{
			"goker.alt": {Ownership: ownRaw, Target: tgtRaw},
		},
	})
	manifestCID := resolver.ComputeRawCIDv1(manifestBytes)
	manifestPath := filepath.Join(tmp, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	prof := &profile.Profile{
		Version:   1,
		NetworkID: "alt-test-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "test-auth-1", PublicKey: records.FormatPublicKey(authPub)},
		},
		Resolver: profile.ResolverConfig{
			ManifestCID: manifestCID,
		},
		ReservedNames: []string{"register"},
	}
	profYAML, _ := yaml.Marshal(prof)
	profPath := filepath.Join(tmp, "profile.yaml")
	if err := os.WriteFile(profPath, profYAML, 0o644); err != nil {
		t.Fatal(err)
	}

	// 2. Sandbox `alt setup` files into `tmp` so `alt doctor` inspects real generated resolver & PF files
	resDir := filepath.Join(tmp, "etc", "resolver")
	pfDir := filepath.Join(tmp, "etc", "pf.anchors")
	ldDir := filepath.Join(tmp, "Library", "LaunchDaemons")
	laDir := filepath.Join(tmp, "Users", "goker", "Library", "LaunchAgents")

	if _, err := captureStdout(t, func() error {
		return runSetup([]string{
			"--profile", profPath,
			"--state-dir", stateDir,
			"--resolver-dir", resDir,
			"--pf-anchors-dir", pfDir,
			"--launch-daemons-dir", ldDir,
			"--launch-agents-dir", laDir,
			"--skip-os-commands",
			"--json",
		})
	}); err != nil {
		t.Fatalf("runSetup sandbox: %v", err)
	}

	// 3. Start the daemon (`--daemon`) in-process
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyCh := make(chan foregroundRuntimeInfo, 1)
	doneCh := make(chan error, 1)

	go func() {
		doneCh <- runForegroundWithContext(ctx, []string{
			"--daemon",
			"--profile", profPath,
			"--manifest-file", manifestPath,
			"--listen", "127.0.0.1:0",
			"--dns-listen", "127.0.0.1:0",
			"--state-dir", stateDir,
		}, readyCh)
	}()

	var info foregroundRuntimeInfo
	select {
	case info = <-readyCh:
	case err := <-doneCh:
		t.Fatalf("daemon exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for daemon startup")
	}

	// Build HTTPS client trusting generated `.alt` Root CA
	caPEM, err := os.ReadFile(info.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	httpsGet := func(host, path string) (*http.Response, string) {
		t.Helper()
		c := &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					ServerName: host,
				},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, info.HTTPSAddr)
				},
			},
		}
		req, err := http.NewRequest(http.MethodGet, "https://"+host+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("GET https://%s%s failed: %v", host, path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}

	// 4. Start local upstream app and bind `goker.alt` via `alt dev goker.alt --port <port>`
	appV1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello-from-local-goker-alt:" + r.URL.Path))
	}))
	defer appV1.Close()
	_, appV1Port, _ := net.SplitHostPort(appV1.Listener.Addr().String())

	if _, err := captureStdout(t, func() error {
		return runDev([]string{
			"goker.alt",
			"--port", appV1Port,
			"--profile", profPath,
			"--state-dir", stateDir,
		})
	}); err != nil {
		t.Fatalf("runDev --port: %v", err)
	}

	resp, body := httpsGet("goker.alt", "/dashboard")
	if resp.StatusCode != http.StatusOK || body != "hello-from-local-goker-alt:/dashboard" {
		t.Fatalf("expected local override response, got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Alt-Resolution") != "local-override" {
		t.Fatalf("expected X-Alt-Resolution=local-override, got %q", resp.Header.Get("X-Alt-Resolution"))
	}

	// 5. Test `alt dev static.alt --dir <dir> --spa`
	staticDir := filepath.Join(tmp, "public")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("spa-index-ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error {
		return runDev([]string{
			"static.alt",
			"--dir", staticDir,
			"--spa",
			"--profile", profPath,
			"--state-dir", stateDir,
		})
	}); err != nil {
		t.Fatalf("runDev --dir --spa: %v", err)
	}
	_, spaBody := httpsGet("static.alt", "/client/route")
	if spaBody != "spa-index-ok" {
		t.Fatalf("expected SPA fallback body spa-index-ok, got %q", spaBody)
	}

	// 6. Test `alt dev multi.alt --route ...`
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api-v1"))
	}))
	defer apiSrv.Close()
	_, apiPort, _ := net.SplitHostPort(apiSrv.Listener.Addr().String())

	if _, err := captureStdout(t, func() error {
		return runDev([]string{
			"multi.alt",
			"--route", "/api/*=" + apiPort,
			"--route", "/*=" + appV1Port,
			"--profile", profPath,
			"--state-dir", stateDir,
		})
	}); err != nil {
		t.Fatalf("runDev --route: %v", err)
	}
	_, multiAPIBody := httpsGet("multi.alt", "/api/users")
	if multiAPIBody != "api-v1" {
		t.Fatalf("expected api-v1, got %q", multiAPIBody)
	}

	// 7. Test `alt list --json` and `alt status --json`
	listJSON, err := captureStdout(t, func() error {
		return runList([]string{"--profile", profPath, "--state-dir", stateDir, "--json"})
	})
	if err != nil {
		t.Fatalf("runList --json: %v", err)
	}
	if !strings.Contains(listJSON, `"goker.alt"`) || !strings.Contains(listJSON, `"static.alt"`) || !strings.Contains(listJSON, `"multi.alt"`) {
		t.Fatalf("expected all 3 domains in alt list --json:\n%s", listJSON)
	}

	statusJSON, err := captureStdout(t, func() error {
		return runStatus([]string{"--profile", profPath, "--state-dir", stateDir, "--json"})
	})
	if err != nil {
		t.Fatalf("runStatus --json: %v", err)
	}
	if !strings.Contains(statusJSON, `"running"`) || !strings.Contains(statusJSON, `"persistentBacked": true`) {
		t.Fatalf("unexpected alt status --json:\n%s", statusJSON)
	}

	// 8. Test `alt halt goker.alt` -> immediately restores signed network record resolution!
	if _, err := captureStdout(t, func() error {
		return runHalt([]string{"goker.alt", "--profile", profPath, "--state-dir", stateDir})
	}); err != nil {
		t.Fatalf("runHalt goker.alt: %v", err)
	}
	haltResp, _ := httpsGet("goker.alt", "/")
	if haltResp.Header.Get("X-Alt-Error-Code") != "DIRECT_CONNECT_FAILED" {
		t.Fatalf("expected goker.alt after halt to resolve signed record and hit SSRF guard, got status=%d code=%q",
			haltResp.StatusCode, haltResp.Header.Get("X-Alt-Error-Code"))
	}

	// 9. Test `alt dev --config alt.yaml` + live `alt daemon reload`
	appV2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cfg-reloaded-v2"))
	}))
	defer appV2.Close()
	_, appV2Port, _ := net.SplitHostPort(appV2.Listener.Addr().String())

	altYAMLPath := filepath.Join(tmp, "alt.yaml")
	cfgV1 := "version: 1\nsites:\n  cfg.alt:\n    routes:\n      - match: /*\n        upstream: http://127.0.0.1:" + appV1Port + "\n"
	if err := os.WriteFile(altYAMLPath, []byte(cfgV1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error {
		return runDev([]string{"--config", altYAMLPath, "--profile", profPath, "--state-dir", stateDir})
	}); err != nil {
		t.Fatalf("runDev --config: %v", err)
	}
	_, cfgBody1 := httpsGet("cfg.alt", "/")
	if !strings.HasPrefix(cfgBody1, "hello-from-local-goker-alt:") {
		t.Fatalf("unexpected initial alt.yaml response: %q", cfgBody1)
	}

	// Update alt.yaml on disk to point to appV2 and run `alt daemon reload`
	cfgV2 := "version: 1\nsites:\n  cfg.alt:\n    routes:\n      - match: /*\n        upstream: http://127.0.0.1:" + appV2Port + "\n"
	if err := os.WriteFile(altYAMLPath, []byte(cfgV2), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := captureStdout(t, func() error {
		return runDaemonReload([]string{"--profile", profPath, "--state-dir", stateDir})
	}); err != nil {
		t.Fatalf("runDaemonReload: %v", err)
	}
	_, cfgBody2 := httpsGet("cfg.alt", "/")
	if cfgBody2 != "cfg-reloaded-v2" {
		t.Fatalf("expected cfg-reloaded-v2 after reload, got %q", cfgBody2)
	}

	// 10. Test `alt doctor --json` against live running daemon + sandboxed receipt
	docOut, err := captureStdout(t, func() error {
		return runDoctor([]string{"--profile", profPath, "--state-dir", stateDir, "--json"})
	})
	if err != nil {
		t.Fatalf("runDoctor --json failed: %v\n%s", err, docOut)
	}
	if !strings.Contains(docOut, `"healthy": true`) {
		t.Fatalf("expected healthy=true in doctor report:\n%s", docOut)
	}

	cancel()
	<-doneCh

	// 11. Test sandboxed `alt uninstall`
	if _, err := captureStdout(t, func() error {
		return runUninstall([]string{
			"--profile", profPath,
			"--state-dir", stateDir,
			"--resolver-dir", resDir,
			"--pf-anchors-dir", pfDir,
			"--launch-daemons-dir", ldDir,
			"--launch-agents-dir", laDir,
			"--skip-os-commands",
		})
	}); err != nil {
		t.Fatalf("runUninstall sandbox: %v", err)
	}
}

func TestSubprocessDaemonStartStopAndReleaseErgonomics(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "alt")

	buildCmd := exec.Command("go", "build", "-ldflags", "-X main.Version=1.2.3-test -X main.Commit=abc1234", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build alt binary: %v\n%s", err, string(out))
	}

	// 1. Verify `alt version --json` and `alt completion zsh`
	verOut, err := exec.Command(binPath, "version", "--json").CombinedOutput()
	if err != nil {
		t.Fatalf("alt version --json: %v\n%s", err, string(verOut))
	}
	if !strings.Contains(string(verOut), `"1.2.3-test"`) || !strings.Contains(string(verOut), `"abc1234"`) {
		t.Fatalf("unexpected version output: %s", string(verOut))
	}

	for _, sh := range []string{"zsh", "bash", "fish"} {
		compOut, err := exec.Command(binPath, "completion", sh).CombinedOutput()
		if err != nil || len(compOut) < 50 {
			t.Fatalf("alt completion %s failed: %v\n%s", sh, err, string(compOut))
		}
	}

	// 2. Verify P2P target mode is explicitly rejected in `alt publish`
	pubOut, pubErr := exec.Command(binPath, "publish", "goker.alt", "--mode", "p2p", "--target", "webrtc://peer").CombinedOutput()
	if pubErr == nil || !strings.Contains(string(pubOut), "disabled") {
		t.Fatalf("expected P2P publish mode to be rejected as beta/disabled, got err=%v out=%s", pubErr, string(pubOut))
	}

	// 3. Verify `alt profile update` & `alt profile show --json`
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	baseProf := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "key-1", PublicKey: "ed25519:" + base64.StdEncoding.EncodeToString(oldPub)},
		},
	}
	baseProfBytes, _ := yaml.Marshal(baseProf)
	baseProfPath := filepath.Join(tmp, "base-profile.yaml")
	_ = os.WriteFile(baseProfPath, baseProfBytes, 0o644)

	nextProf := baseProf.Clone()
	nextProf.RegistryKeys = append(nextProf.RegistryKeys, profile.RegistryKey{
		ID:        "key-2",
		PublicKey: "ed25519:" + base64.StdEncoding.EncodeToString(newPub),
	})
	now := time.Now().UTC().Truncate(time.Second)
	bundle := &profile.SignedProfileBundle{
		Schema:      profile.SchemaProfileBundleV1,
		NetworkID:   "alt-main-v1",
		Sequence:    1,
		IssuedAt:    now.Add(-5 * time.Minute).Format(time.RFC3339),
		ExpiresAt:   now.Add(24 * time.Hour).Format(time.RFC3339),
		SignerKeyID: "key-1",
		Profile:     *nextProf,
	}
	_ = bundle.Sign(oldPriv)
	bundleJSON, _ := json.Marshal(bundle)
	bundlePath := filepath.Join(tmp, "bundle.json")
	_ = os.WriteFile(bundlePath, bundleJSON, 0o644)

	stateDir := filepath.Join(tmp, "daemon-state")
	if out, err := exec.Command(binPath, "profile", "update", bundlePath, "--profile", baseProfPath, "--state-dir", stateDir).CombinedOutput(); err != nil {
		t.Fatalf("alt profile update: %v\n%s", err, string(out))
	}
	showOut, err := exec.Command(binPath, "profile", "show", "--state-dir", stateDir, "--json").CombinedOutput()
	if err != nil || !strings.Contains(string(showOut), `"key-2"`) {
		t.Fatalf("expected rotated key-2 in alt profile show --json: err=%v out=%s", err, string(showOut))
	}

	// 4. Spawn real background daemon subprocess with free ports, verify status + logs, then stop cleanly
	freePort := func() int {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		return p
	}
	httpsPort := freePort()
	dnsPort := freePort()

	startOut, err := exec.Command(
		binPath, "daemon", "start",
		"--listen", "127.0.0.1:"+strconv.Itoa(httpsPort),
		"--dns-listen", "127.0.0.1:"+strconv.Itoa(dnsPort),
		"--state-dir", stateDir,
		"--json",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("alt daemon start: %v\n%s", err, string(startOut))
	}
	defer func() {
		_ = exec.Command(binPath, "daemon", "stop", "--state-dir", stateDir).Run()
	}()

	logsOut, err := exec.Command(binPath, "daemon", "logs", "--state-dir", stateDir).CombinedOutput()
	if err != nil || !strings.Contains(string(logsOut), "started network=") {
		t.Fatalf("expected daemon logs to contain startup line: err=%v out=%s", err, string(logsOut))
	}

	stopOut, err := exec.Command(binPath, "daemon", "stop", "--state-dir", stateDir, "--json").CombinedOutput()
	if err != nil || !strings.Contains(string(stopOut), `"wasRunning": true`) {
		t.Fatalf("alt daemon stop: err=%v out=%s", err, string(stopOut))
	}
}
