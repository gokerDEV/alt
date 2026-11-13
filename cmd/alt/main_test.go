package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"alt/pkg/dnsstub"
	"alt/pkg/profile"
	"alt/pkg/records"
	"alt/pkg/resolver"
	"gopkg.in/yaml.v3"
)

func TestForegroundRunEndToEndSmoke(t *testing.T) {
	// 1. Start a local upstream HTTP application
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Proto", r.Header.Get("X-Forwarded-Proto"))
		w.Header().Set("X-Seen-Host", r.Header.Get("X-Forwarded-Host"))
		_, _ = w.Write([]byte("register-local-app-ok"))
	}))
	defer upstream.Close()

	_, upstreamPortStr, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	stateDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	readyCh := make(chan foregroundRuntimeInfo, 1)
	doneCh := make(chan error, 1)

	go func() {
		doneCh <- runForegroundWithContext(ctx, []string{
			"register.alt",
			"--port", upstreamPortStr,
			"--listen", "127.0.0.1:0",
			"--dns-listen", "127.0.0.1:0",
			"--state-dir", stateDir,
			"--tld", "alt",
		}, readyCh)
	}()

	var info foregroundRuntimeInfo
	select {
	case info = <-readyCh:
	case err := <-doneCh:
		t.Fatalf("runForeground exited early: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for foreground server startup")
	}

	// Verify CA private key permissions are strictly 0600
	keyStat, err := os.Stat(filepath.Join(stateDir, "ca.key"))
	if err != nil {
		t.Fatalf("stat ca.key: %v", err)
	}
	if perm := keyStat.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected ca.key permissions 0600, got %o", perm)
	}

	// 2. Verify UDP DNS stub answers .alt queries and refuses .com queries
	dnsConn, err := net.DialTimeout("udp", info.DNSAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial DNS stub: %v", err)
	}
	defer dnsConn.Close()
	_ = dnsConn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := dnsConn.Write(dnsstub.EncodeQuery(0x4242, "register.alt", 1)); err != nil {
		t.Fatal(err)
	}
	dnsResp := make([]byte, 512)
	n, err := dnsConn.Read(dnsResp)
	if err != nil {
		t.Fatalf("read DNS response: %v", err)
	}
	if binary.BigEndian.Uint16(dnsResp[:n][6:8]) != 1 {
		t.Fatalf("expected 1 DNS answer for register.alt")
	}

	if _, err := dnsConn.Write(dnsstub.EncodeQuery(0x4243, "example.com", 1)); err != nil {
		t.Fatal(err)
	}
	nRefused, err := dnsConn.Read(dnsResp)
	if err != nil {
		t.Fatal(err)
	}
	if rcode := dnsResp[:nRefused][3] & 0x0F; rcode != 5 {
		t.Fatalf("expected REFUSED (5) for example.com, got %d", rcode)
	}

	// 3. Verify HTTPS leaf certificate is trusted by generated CA and constrained to .alt
	caPEM, err := os.ReadFile(info.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse generated ca.crt")
	}

	httpsClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "register.alt",
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, info.HTTPSAddr)
			},
		},
	}

	resp, err := httpsClient.Get("https://register.alt/health")
	if err != nil {
		t.Fatalf("HTTPS GET register.alt failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "register-local-app-ok" {
		t.Fatalf("unexpected HTTPS response: %d %q", resp.StatusCode, string(body))
	}
	if resp.Header.Get("X-Alt-Resolution") != "local-override" {
		t.Fatalf("expected local-override header, got %q", resp.Header.Get("X-Alt-Resolution"))
	}
	if resp.Header.Get("X-Seen-Proto") != "https" {
		t.Fatalf("expected X-Forwarded-Proto=https, got %q", resp.Header.Get("X-Seen-Proto"))
	}

	// 4. Verify TLS handshake fails for out-of-namespace SNI (e.g. example.com or register.mesh)
	badSNIClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "register.mesh",
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, info.HTTPSAddr)
			},
		},
	}
	if _, err := badSNIClient.Get("https://register.mesh/"); err == nil {
		t.Fatalf("expected TLS handshake failure for out-of-namespace SNI register.mesh")
	}

	// 5. Verify graceful shutdown on context cancellation
	cancel()
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("expected clean shutdown, got error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for graceful shutdown")
	}
}

func TestForegroundRunIPFSProfileMode(t *testing.T) {
	// Test running `alt run --profile ...` without --port, verifying IPFS gateway manifest fetch & error classification
	authPub, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)

	now := time.Now().UTC().Add(-1 * time.Minute)
	exp := now.Add(24 * time.Hour)

	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      "mesh-net-v1",
		Domain:         "register.mesh",
		AccountID:      "acct_mesh",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      exp.Format(time.RFC3339),
		IssuerKeyID:    "mesh-key-1",
	}
	_ = cert.Sign(authPriv)

	// Target points to 127.0.0.1 which default production Engine SSRF guard blocks with DIRECT_CONNECT_FAILED,
	// proving that manifest CID fetch + signature verification succeeded and dispatched to HTTPS target handler!
	target := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           "mesh-net-v1",
		Domain:              "register.mesh",
		OwnershipGeneration: 1,
		Sequence:            1,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://127.0.0.1:9443",
		IssuedAt:            now.Format(time.RFC3339),
		ExpiresAt:           exp.Format(time.RFC3339),
	}
	_ = target.Sign(ownerPriv)

	ownRaw, _ := json.Marshal(cert)
	tgtRaw, _ := json.Marshal(target)
	manifestBytes, _ := json.Marshal(resolver.Manifest{
		Schema:    resolver.SchemaManifestV1,
		NetworkID: "mesh-net-v1",
		Records: map[string]resolver.ManifestEntry{
			"register.mesh": {Ownership: ownRaw, Target: tgtRaw},
		},
	})
	cid := resolver.ComputeRawCIDv1(manifestBytes)

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.ipld.raw")
		_, _ = w.Write(manifestBytes)
	}))
	defer gw.Close()

	prof := &profile.Profile{
		Version:   1,
		NetworkID: "mesh-net-v1",
		TLD:       "mesh",
		RegistryKeys: []profile.RegistryKey{
			{ID: "mesh-key-1", PublicKey: records.FormatPublicKey(authPub)},
		},
		Resolver: profile.ResolverConfig{
			ManifestCID: cid,
			Gateways:    []string{gw.URL},
		},
		ReservedNames: []string{"register"},
	}
	profYAML, _ := yaml.Marshal(prof)
	tmpDir := t.TempDir()
	profPath := filepath.Join(tmpDir, "mesh-profile.yaml")
	if err := os.WriteFile(profPath, profYAML, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyCh := make(chan foregroundRuntimeInfo, 1)
	doneCh := make(chan error, 1)

	go func() {
		doneCh <- runForegroundWithContext(ctx, []string{
			"--profile", profPath,
			"--listen", "127.0.0.1:0",
			"--state-dir", filepath.Join(tmpDir, "ca"),
		}, readyCh)
	}()

	info := <-readyCh
	caPEM, _ := os.ReadFile(info.CertPath)
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "register.mesh",
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, info.HTTPSAddr)
			},
		},
	}

	// Query unknown.mesh -> 404 NAME_NOT_FOUND
	unknownClient := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    roots,
				ServerName: "unknown.mesh",
			},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, info.HTTPSAddr)
			},
		},
	}
	rUnknown, err := unknownClient.Get("https://unknown.mesh/")
	if err != nil {
		t.Fatalf("GET unknown.mesh failed: %v", err)
	}
	rUnknown.Body.Close()
	if rUnknown.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown.mesh, got %d", rUnknown.StatusCode)
	}

	// Query register.mesh -> resolves signed record via IPFS gateway and enforces private-IP guard (502 DIRECT_CONNECT_FAILED)
	rReg, err := client.Get("https://register.mesh/")
	if err != nil {
		t.Fatalf("GET register.mesh failed: %v", err)
	}
	regBody, _ := io.ReadAll(rReg.Body)
	rReg.Body.Close()
	if rReg.Header.Get("X-Alt-Error-Code") != "DIRECT_CONNECT_FAILED" || !strings.Contains(string(regBody), "disallowed private, loopback") {
		t.Fatalf("expected SSRF loopback protection after IPFS record verification, got status=%d code=%q body=%q",
			rReg.StatusCode, rReg.Header.Get("X-Alt-Error-Code"), string(regBody))
	}

	// Also verify non-loopback listen rejection
	if err := runForegroundWithContext(context.Background(), []string{
		"register.mesh",
		"--port", strconv.Itoa(8080),
		"--listen", "0.0.0.0:8443",
	}, nil); err == nil {
		t.Fatalf("expected non-loopback --listen 0.0.0.0:8443 to be rejected")
	}

	cancel()
	<-doneCh
}

func TestForegroundRunExitsWhenDNSStubFails(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	_, portStr, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyCh := make(chan foregroundRuntimeInfo, 1)
	doneCh := make(chan error, 1)

	go func() {
		doneCh <- runForegroundWithContext(ctx, []string{
			"register.alt",
			"--port", portStr,
			"--listen", "127.0.0.1:0",
			"--dns-listen", "127.0.0.1:0",
			"--state-dir", t.TempDir(),
		}, readyCh)
	}()

	info := <-readyCh
	// Simulate unexpected DNS socket closure while ctx is still active
	_ = info.DNSConn.Close()

	select {
	case err := <-doneCh:
		if err == nil || !strings.Contains(err.Error(), "DNS stub stopped unexpectedly") {
			t.Fatalf("expected DNS stub failure error, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("expected CLI to shut down promptly when DNS stub fails")
	}
}
