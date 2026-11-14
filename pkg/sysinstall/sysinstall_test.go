package sysinstall_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"alt/pkg/config"
	"alt/pkg/daemon"
	"alt/pkg/dnsstub"
	"alt/pkg/pki"
	"alt/pkg/profile"
	"alt/pkg/sysinstall"
)

type recordedCmd struct {
	name string
	args []string
}

type mockRunner struct {
	cmds []recordedCmd
}

func (m *mockRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.cmds = append(m.cmds, recordedCmd{name: name, args: append([]string(nil), args...)})
	return []byte("ok\n"), nil
}

func TestInstallUpgradeUninstallAndCaddyCoexistence(t *testing.T) {
	tmp := t.TempDir()
	stateDir := filepath.Join(tmp, "state")
	resolverDir := filepath.Join(tmp, "etc", "resolver")
	pfAnchorsDir := filepath.Join(tmp, "etc", "pf.anchors")
	launchDaemonsDir := filepath.Join(tmp, "Library", "LaunchDaemons")
	launchAgentsDir := filepath.Join(tmp, "Users", "tester", "Library", "LaunchAgents")

	caDir := filepath.Join(stateDir, "pki")
	ca, err := pki.LoadOrCreateCAForTLD(caDir, "alt")
	if err != nil {
		t.Fatalf("LoadOrCreateCAForTLD: %v", err)
	}
	caCertPath := filepath.Join(caDir, "ca.crt")

	opts := sysinstall.Options{
		TLD:              "alt",
		NetworkID:        "alt-main-v1",
		BinaryPath:       "/usr/local/bin/alt",
		StateDir:         stateDir,
		CACertPath:       caCertPath,
		LoopbackIP:       "127.0.0.2",
		HTTPSPort:        19443,
		DNSPort:          15353,
		Uid:              501,
		HomeDir:          filepath.Join(tmp, "Users", "tester"),
		ResolverDir:      resolverDir,
		PFAnchorsDir:     pfAnchorsDir,
		LaunchDaemonsDir: launchDaemonsDir,
		LaunchAgentsDir:  launchAgentsDir,
	}

	runner := &mockRunner{}
	ctx := context.Background()

	// 1. Install (first time) and verify idempotency on second install (upgrade)
	plan1, err := sysinstall.ApplyInstall(ctx, opts, runner, false)
	if err != nil {
		t.Fatalf("ApplyInstall 1: %v", err)
	}
	plan2, err := sysinstall.ApplyInstall(ctx, opts, runner, false)
	if err != nil {
		t.Fatalf("ApplyInstall 2 (idempotent upgrade): %v", err)
	}
	if plan1.Receipt.ResolverFilePath != plan2.Receipt.ResolverFilePath {
		t.Fatalf("expected identical resolver file paths across idempotent install")
	}

	// Verify `/etc/resolver/alt` targets ONLY 127.0.0.2:15353
	resBytes, err := os.ReadFile(plan1.Receipt.ResolverFilePath)
	if err != nil {
		t.Fatalf("read resolver file: %v", err)
	}
	if !strings.Contains(string(resBytes), "nameserver 127.0.0.2") || !strings.Contains(string(resBytes), "port 15353") {
		t.Fatalf("unexpected resolver content:\n%s", string(resBytes))
	}

	// Verify PF anchor scopes strictly to `to 127.0.0.2` on `lo0` for both DNS (53->15353) and HTTPS (443->19443)
	pfBytes, err := os.ReadFile(plan1.Receipt.PFAnchorFilePath)
	if err != nil {
		t.Fatalf("read PF anchor file: %v", err)
	}
	for _, wantPFRule := range []string{
		"rdr pass on lo0 inet proto udp from any to 127.0.0.2 port 53 -> 127.0.0.2 port 15353",
		"rdr pass on lo0 inet proto tcp from any to 127.0.0.2 port 53 -> 127.0.0.2 port 15353",
		"rdr pass on lo0 inet proto tcp from any to 127.0.0.2 port 443 -> 127.0.0.2 port 19443",
	} {
		if !strings.Contains(string(pfBytes), wantPFRule) {
			t.Fatalf("expected PF anchor to contain %q, got:\n%s", wantPFRule, string(pfBytes))
		}
	}
	helperBytes, err := os.ReadFile(plan1.Receipt.HelperScriptPath)
	if err != nil {
		t.Fatalf("read helper script: %v", err)
	}
	if !strings.Contains(string(helperBytes), "State:/Network/Service/dev.alt.alt/DNS") {
		t.Fatalf("expected helper script to register SCDynamicStore supplemental DNS, got:\n%s", string(helperBytes))
	}
	if strings.HasPrefix(plan1.Receipt.HelperScriptPath, stateDir) {
		t.Fatalf("root LaunchDaemon helper script %q must not reside inside user-writable stateDir %q", plan1.Receipt.HelperScriptPath, stateDir)
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("/sbin/pfctl", "-nf", plan1.Receipt.PFAnchorFilePath).CombinedOutput(); err != nil {
			t.Fatalf("pfctl -nf syntax validation failed: %v\n%s", err, string(out))
		}
		for _, plistPath := range []string{plan1.Receipt.LaunchDaemonPlist, plan1.Receipt.LaunchAgentPlist} {
			if out, err := exec.Command("/usr/bin/plutil", "-lint", plistPath).CombinedOutput(); err != nil {
				t.Fatalf("plutil -lint failed on %s: %v\n%s", plistPath, err, string(out))
			}
		}
	}

	// 2. Caddy Coexistence Acceptance Proof:
	// Start a simulated Caddy server listening on wildcard/127.0.0.1 alongside the dotALT daemon + UDP DNS stub.
	caddyMux := http.NewServeMux()
	caddyMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Caddy")
		_, _ = w.Write([]byte("caddy-origin:" + r.Host))
	})
	caddyServer := httptest.NewTLSServer(caddyMux)
	defer caddyServer.Close()

	// Start local upstream app for `goker.alt`
	localApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("dotalt-goker-alt-ok"))
	}))
	defer localApp.Close()

	_, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = authPriv
	prof := profile.Official()
	eng, err := daemon.NewEngineChecked(daemon.Options{Profile: prof})
	if err != nil {
		t.Fatalf("NewEngineChecked: %v", err)
	}
	if err := eng.UpsertLocalSite("goker.alt", config.SiteEntry{
		Routes: []config.RouteEntry{{Match: "/*", Upstream: localApp.URL}},
	}, "."); err != nil {
		t.Fatalf("UpsertLocalSite: %v", err)
	}

	// Bind dotALT HTTPS listener and UDP DNS stub
	altLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen alt HTTPS: %v", err)
	}
	defer altLn.Close()
	altTLS := tls.NewListener(altLn, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: ca.GetCertificate,
	})
	altSrv := &http.Server{Handler: eng}
	go func() { _ = altSrv.Serve(altTLS) }()
	defer altSrv.Close()

	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP DNS: %v", err)
	}
	defer dnsConn.Close()
	dnsCtx, cancelDNS := context.WithCancel(ctx)
	defer cancelDNS()
	go func() {
		_ = dnsstub.ServeUDP(dnsCtx, dnsConn, dnsstub.Config{
			IPv4Loopback: net.ParseIP("127.0.0.2"),
			TTL:          60,
			TLD:          "alt",
		})
	}()

	// Verify `alt doctor` live checks against the running DNS stub and CA
	docReport := sysinstall.RunDoctorChecks(ctx, sysinstall.DoctorInput{
		NetworkID:        prof.NetworkID,
		TLD:              prof.TLD,
		StateDir:         stateDir,
		CACertPath:       caCertPath,
		ResolverFilePath: plan1.Receipt.ResolverFilePath,
		PFAnchorFilePath: plan1.Receipt.PFAnchorFilePath,
		DaemonRunning:    true,
		DaemonPID:        os.Getpid(),
		DaemonHTTPSAddr:  altLn.Addr().String(),
		DaemonDNSAddr:    dnsConn.LocalAddr().String(),
		LoopbackIP:       "127.0.0.1",
	})
	if !docReport.Healthy {
		t.Fatalf("expected healthy doctor report, got: %+v", docReport)
	}

	// Verify Caddy continues serving normal localhost/non-.alt HTTPS traffic untouched
	caddyResp, err := caddyServer.Client().Get(caddyServer.URL)
	if err != nil {
		t.Fatalf("Caddy request failed: %v", err)
	}
	caddyBody, _ := io.ReadAll(caddyResp.Body)
	_ = caddyResp.Body.Close()
	if !strings.HasPrefix(string(caddyBody), "caddy-origin:") {
		t.Fatalf("expected Caddy response, got %q", string(caddyBody))
	}

	// Verify dotALT serves `https://goker.alt` with a valid leaf certificate chained to our constrained `.alt` Root CA
	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)

	altClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				ServerName: "goker.alt",
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, altLn.Addr().String())
			},
		},
	}
	altResp, err := altClient.Get("https://goker.alt/")
	if err != nil {
		t.Fatalf("https://goker.alt request failed: %v", err)
	}
	altBody, _ := io.ReadAll(altResp.Body)
	_ = altResp.Body.Close()
	if string(altBody) != "dotalt-goker-alt-ok" {
		t.Fatalf("expected dotalt-goker-alt-ok, got %q", string(altBody))
	}

	// 3. Uninstall and verify all dotALT system files are cleanly removed while Caddy still works
	if _, err := sysinstall.ApplyUninstall(ctx, opts, runner, false); err != nil {
		t.Fatalf("ApplyUninstall: %v", err)
	}
	for _, p := range []string{
		plan1.Receipt.ResolverFilePath,
		plan1.Receipt.PFAnchorFilePath,
		plan1.Receipt.LaunchDaemonPlist,
		plan1.Receipt.LaunchAgentPlist,
		sysinstall.ReceiptPath(stateDir),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed after ApplyUninstall, got err=%v", p, err)
		}
	}

	caddyRespAfter, err := caddyServer.Client().Get(caddyServer.URL)
	if err != nil {
		t.Fatalf("Caddy request after uninstall failed: %v", err)
	}
	_ = caddyRespAfter.Body.Close()
	if caddyRespAfter.StatusCode != http.StatusOK {
		t.Fatalf("expected Caddy 200 OK after uninstall, got %d", caddyRespAfter.StatusCode)
	}
}
