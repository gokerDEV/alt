package daemon_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"alt/pkg/config"
	"alt/pkg/daemon"
	alterrors "alt/pkg/errors"
	"alt/pkg/profile"
	"alt/pkg/records"
	"alt/pkg/resolver"
)

func TestEngineAtomicReloadAndRollbackProtection(t *testing.T) {
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	eng := daemon.NewEngine(authPub)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok-v1"))
	}))
	defer upstream.Close()

	validSite := config.SiteEntry{
		Routes: []config.RouteEntry{
			{Match: "/*", Upstream: upstream.URL},
		},
	}
	if err := eng.UpsertLocalSite("local.alt", validSite, t.TempDir()); err != nil {
		t.Fatalf("UpsertLocalSite failed: %v", err)
	}

	// Reject a .mesh site in an .alt engine
	if err := eng.UpsertLocalSite("local.mesh", validSite, t.TempDir()); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected INVALID_CONFIG when adding .mesh site to .alt engine, got: %v", err)
	}

	// Invalid reload must not break the active site configuration (§17)
	invalidSite := config.SiteEntry{
		Routes: []config.RouteEntry{},
	}
	if err := eng.UpsertLocalSite("local.alt", invalidSite, t.TempDir()); err == nil {
		t.Fatalf("expected error on invalid site reload")
	}

	req := httptest.NewRequest(http.MethodGet, "https://local.alt/", nil)
	rec := httptest.NewRecorder()
	eng.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "ok-v1" {
		t.Fatalf("expected existing local site to remain intact after invalid reload, got %d %q", rec.Code, rec.Body.String())
	}

	// Verify monotonic sequence anti-rollback protection (§8, §17)
	now := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      profile.DefaultNetworkID,
		Domain:         "goker.alt",
		AccountID:      "acct_1",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       "2026-11-03T00:00:00Z",
		ExpiresAt:      "2036-11-03T00:00:00Z",
		IssuerKeyID:    "reg-1",
	}
	_ = cert.Sign(authPriv)

	tSeq5 := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           profile.DefaultNetworkID,
		Domain:              "goker.alt",
		OwnershipGeneration: 1,
		Sequence:            5,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://v5.example.com",
		IssuedAt:            "2026-11-03T00:00:00Z",
		ExpiresAt:           "2027-11-03T00:00:00Z",
	}
	_ = tSeq5.Sign(ownerPriv)

	if err := eng.IngestSignedRecords(cert, tSeq5, now); err != nil {
		t.Fatalf("IngestSignedRecords seq 5 failed: %v", err)
	}

	tSeq4 := *tSeq5
	tSeq4.Sequence = 4
	_ = tSeq4.Sign(ownerPriv)
	if err := eng.IngestSignedRecords(cert, &tSeq4, now); err == nil {
		t.Fatalf("expected rollback error when ingesting sequence 4 after sequence 5")
	}

	// Verify .mesh record cannot enter an .alt engine
	meshCert := *cert
	meshCert.Domain = "goker.mesh"
	_ = meshCert.Sign(authPriv)
	meshTarget := *tSeq5
	meshTarget.Domain = "goker.mesh"
	meshTarget.Sequence = 6
	_ = meshTarget.Sign(ownerPriv)
	if err := eng.IngestSignedRecords(&meshCert, &meshTarget, now); err == nil {
		t.Fatalf("expected .mesh record to be rejected in .alt engine")
	}
}

func TestLocalOverridePrecedenceAndIPFSFallback(t *testing.T) {
	// 1. Start a local app (override) and a verified HTTPS target origin
	localApp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("served-by-local-override"))
	}))
	defer localApp.Close()

	verifiedOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Alt-Domain", r.Header.Get("X-Alt-Domain"))
		_, _ = w.Write([]byte("served-by-verified-ipfs-target"))
	}))
	defer verifiedOrigin.Close()

	// 2. Sign ownership + target records for register.alt pointing to verifiedOrigin.URL
	authPub, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	prof := &profile.Profile{
		Version:   1,
		NetworkID: "alt-demo-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "dev-registry-2026", PublicKey: records.FormatPublicKey(authPub)},
		},
		ReservedNames: []string{"register"},
	}
	if err := prof.Validate(); err != nil {
		t.Fatal(err)
	}

	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      prof.NetworkID,
		Domain:         "register.alt",
		AccountID:      "acct_registry",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       "2026-11-12T00:00:00Z",
		ExpiresAt:      "2030-11-12T00:00:00Z",
		IssuerKeyID:    "dev-registry-2026",
	}
	_ = cert.Sign(authPriv)

	target := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           prof.NetworkID,
		Domain:              "register.alt",
		OwnershipGeneration: 1,
		Sequence:            1,
		Mode:                records.TargetModeHTTPS,
		Target:              verifiedOrigin.URL,
		IssuedAt:            "2026-11-12T00:00:00Z",
		ExpiresAt:           "2027-11-12T00:00:00Z",
	}
	_ = target.Sign(ownerPriv)

	ownRaw, _ := json.Marshal(cert)
	tgtRaw, _ := json.Marshal(target)
	manifestBytes, _ := json.Marshal(resolver.Manifest{
		Schema:    resolver.SchemaManifestV1,
		NetworkID: prof.NetworkID,
		Records: map[string]resolver.ManifestEntry{
			"register.alt": {Ownership: ownRaw, Target: tgtRaw},
		},
	})
	manifestCID := resolver.ComputeRawCIDv1(manifestBytes)

	ipfsGateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.ipld.raw")
		_, _ = w.Write(manifestBytes)
	}))
	defer ipfsGateway.Close()

	gwSource, err := resolver.NewGatewaySource(resolver.GatewayOptions{
		ManifestCID:     manifestCID,
		ExpectedNetwork: prof.NetworkID,
		Gateways:        []string{ipfsGateway.URL},
	})
	if err != nil {
		t.Fatal(err)
	}
	res := resolver.New(prof, gwSource)
	res.SetClock(func() time.Time { return now })

	originPool := x509.NewCertPool()
	originPool.AddCert(verifiedOrigin.Certificate())
	originTransport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: originPool},
	}

	eng, err := daemon.NewEngineChecked(daemon.Options{
		Profile:            prof,
		Resolver:           res,
		OriginTransport:    originTransport,
		AllowLoopbackHTTPS: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Activate local override for register.alt -> local override MUST win over IPFS
	if err := eng.UpsertLocalSite("register.alt", config.SiteEntry{
		Routes: []config.RouteEntry{{Match: "/*", Upstream: localApp.URL}},
	}, t.TempDir()); err != nil {
		t.Fatal(err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "https://register.alt/", nil)
	rec1 := httptest.NewRecorder()
	eng.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || rec1.Body.String() != "served-by-local-override" {
		t.Fatalf("expected local override to win, got %d %q", rec1.Code, rec1.Body.String())
	}
	if rec1.Header().Get("X-Alt-Resolution") != "local-override" {
		t.Fatalf("expected X-Alt-Resolution=local-override, got %q", rec1.Header().Get("X-Alt-Resolution"))
	}

	// 4. Remove local override -> verified IPFS resolution takes over seamlessly
	if !eng.RemoveLocalSite("register.alt") {
		t.Fatalf("expected RemoveLocalSite to return true")
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://register.alt/welcome", nil)
	rec2 := httptest.NewRecorder()
	eng.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "served-by-verified-ipfs-target" {
		t.Fatalf("expected verified IPFS fallback response, got %d %q", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("X-Alt-Resolution") != "verified-record" {
		t.Fatalf("expected X-Alt-Resolution=verified-record, got %q", rec2.Header().Get("X-Alt-Resolution"))
	}
	if rec2.Header().Get("X-Seen-Alt-Domain") != "register.alt" {
		t.Fatalf("expected upstream to receive X-Alt-Domain=register.alt, got %q", rec2.Header().Get("X-Seen-Alt-Domain"))
	}

	// 5. Unknown name returns NAME_NOT_FOUND (404)
	req3 := httptest.NewRequest(http.MethodGet, "https://nonexistent.alt/", nil)
	rec3 := httptest.NewRecorder()
	eng.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound || !strings.Contains(rec3.Body.String(), string(alterrors.CodeNameNotFound)) {
		t.Fatalf("expected 404 NAME_NOT_FOUND, got %d %q", rec3.Code, rec3.Body.String())
	}
}

func TestSSRFSpecialUseDenylist(t *testing.T) {
	disallowedAddrs := []string{
		"0.0.0.0",
		"0.1.2.3",             // 0.0.0.0/8 "This network"
		"10.0.0.1",            // RFC 1918
		"100.64.0.1",          // RFC 6598 CGNAT
		"100.127.255.254",     // RFC 6598 CGNAT upper
		"127.0.0.1",           // Loopback
		"127.88.0.1",          // Loopback
		"169.254.169.254",     // Link-Local / Cloud Metadata
		"172.16.0.1",          // RFC 1918
		"192.0.0.1",           // IETF Protocol Assignments
		"192.0.2.1",           // TEST-NET-1
		"192.88.99.1",         // 6to4 Relay Anycast
		"192.168.1.1",         // RFC 1918
		"198.18.0.1",          // Benchmarking
		"198.51.100.1",        // TEST-NET-2
		"203.0.113.1",         // TEST-NET-3
		"224.0.0.1",           // Multicast
		"240.0.0.1",           // Class E Reserved
		"255.255.255.255",     // Broadcast
		"::",                  // Unspecified
		"::1",                 // Loopback
		"::ffff:127.0.0.1",    // IPv4-mapped loopback
		"::ffff:100.64.0.1",   // IPv4-mapped CGNAT
		"::127.0.0.1",         // IPv4-compatible loopback
		"64:ff9b::127.0.0.1",  // NAT64 well-known
		"64:ff9b:1::10.0.0.1", // NAT64 local-use
		"100::1",              // Discard-only
		"2001::1",             // Teredo
		"2001:2::1",           // Benchmarking v6
		"2001:db8::1",         // Documentation v6
		"2002:7f00:0001::1",   // 6to4 embedding 127.0.0.1
		"fc00::1",             // ULA
		"fd12:3456::1",        // ULA
		"fe80::1",             // Link-local
		"ff02::1",             // Multicast
	}
	for _, raw := range disallowedAddrs {
		addr := netip.MustParseAddr(raw)
		if !daemon.IsDisallowedOriginAddr(addr) {
			t.Fatalf("expected IP %s to be disallowed by SSRF guard", raw)
		}
	}

	allowedPublicAddrs := []string{
		"1.1.1.1",
		"8.8.8.8",
		"93.184.215.14",
		"2606:2800:21f:cb07:6820:80da:af6b:8b2c",
		"2606:4700:4700::1111",
	}
	for _, raw := range allowedPublicAddrs {
		addr := netip.MustParseAddr(raw)
		if daemon.IsDisallowedOriginAddr(addr) {
			t.Fatalf("expected public global unicast IP %s to be allowed", raw)
		}
	}

	for _, badHost := range []string{"localhost", "api.localhost", "printer.local", "db.internal", "router.home.arpa", "service.onion"} {
		if !daemon.IsDisallowedOriginHost(badHost) {
			t.Fatalf("expected host %q to be disallowed", badHost)
		}
	}
}

func TestIngestDoesNotMutateSharedTrustProfileAndIsConcurrencySafe(t *testing.T) {
	authPub, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)

	sharedProf := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "reg-2026", PublicKey: records.FormatPublicKey(authPub)},
		},
		ReservedNames: []string{"register"},
	}
	if err := sharedProf.Validate(); err != nil {
		t.Fatal(err)
	}

	// Engine 1 with sharedProf
	engProf, err := daemon.NewEngineChecked(daemon.Options{Profile: sharedProf})
	if err != nil {
		t.Fatal(err)
	}
	// Engine 2 via legacy single-key constructor
	engSingle := daemon.NewEngine(authPub)

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	var wg sync.WaitGroup
	for i := 1; i <= 16; i++ {
		seq := uint64(i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			c := &records.OwnershipCertificate{
				Schema:         records.SchemaOwnershipV1,
				NetworkID:      "alt-main-v1",
				Domain:         "app.alt",
				AccountID:      "acct_1",
				OwnerPublicKey: records.FormatPublicKey(ownerPub),
				Generation:     1,
				IssuedAt:       "2026-11-12T00:00:00Z",
				ExpiresAt:      "2030-11-12T00:00:00Z",
				IssuerKeyID:    "reg-2026",
			}
			_ = c.Sign(authPriv)
			tr := &records.TargetRecord{
				Schema:              records.SchemaTargetV1,
				NetworkID:           "alt-main-v1",
				Domain:              "app.alt",
				OwnershipGeneration: 1,
				Sequence:            seq,
				Mode:                records.TargetModeHTTPS,
				Target:              "https://app.example.com",
				IssuedAt:            "2026-11-12T00:00:00Z",
				ExpiresAt:           "2027-11-12T00:00:00Z",
			}
			_ = tr.Sign(ownerPriv)
			_ = engProf.IngestSignedRecords(c, tr, now)
		}()
		go func() {
			defer wg.Done()
			c := &records.OwnershipCertificate{
				Schema:         records.SchemaOwnershipV1,
				NetworkID:      "alt-main-v1",
				Domain:         "app.alt",
				AccountID:      "acct_1",
				OwnerPublicKey: records.FormatPublicKey(ownerPub),
				Generation:     1,
				IssuedAt:       "2026-11-12T00:00:00Z",
				ExpiresAt:      "2030-11-12T00:00:00Z",
				IssuerKeyID:    "custom-key-id",
			}
			_ = c.Sign(authPriv)
			tr := &records.TargetRecord{
				Schema:              records.SchemaTargetV1,
				NetworkID:           "alt-main-v1",
				Domain:              "app.alt",
				OwnershipGeneration: 1,
				Sequence:            seq,
				Mode:                records.TargetModeHTTPS,
				Target:              "https://app.example.com",
				IssuedAt:            "2026-11-12T00:00:00Z",
				ExpiresAt:           "2027-11-12T00:00:00Z",
			}
			_ = tr.Sign(ownerPriv)
			_ = engSingle.IngestSignedRecords(c, tr, now)
		}()
	}
	wg.Wait()

	// Verify sharedProf was never mutated
	if len(sharedProf.RegistryKeys) != 1 || sharedProf.RegistryKeys[0].ID != "reg-2026" {
		t.Fatalf("shared profile was mutated: %+v", sharedProf.RegistryKeys)
	}
	// Verify engSingle's profile was never mutated with "custom-key-id"
	if len(engSingle.Profile().RegistryKeys) != 0 {
		t.Fatalf("expected single-key engine profile RegistryKeys to remain untouched, got %+v", engSingle.Profile().RegistryKeys)
	}
}

func TestEngineRejectsDisagreeingResolverProfile(t *testing.T) {
	keyA, _, _ := ed25519.GenerateKey(rand.Reader)
	keyB, _, _ := ed25519.GenerateKey(rand.Reader)

	altProf := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "reg-1", PublicKey: records.FormatPublicKey(keyA)},
		},
	}
	_ = altProf.Validate()

	meshProf := &profile.Profile{
		Version:   1,
		NetworkID: "mesh-main-v1",
		TLD:       "mesh",
		RegistryKeys: []profile.RegistryKey{
			{ID: "reg-1", PublicKey: records.FormatPublicKey(keyA)},
		},
	}
	_ = meshProf.Validate()

	diffKeyProf := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "reg-1", PublicKey: records.FormatPublicKey(keyB)},
		},
	}
	_ = diffKeyProf.Validate()

	// 1. Mismatched networkId / TLD between opts.Profile and opts.Resolver
	meshRes := resolver.New(meshProf, nil)
	if _, err := daemon.NewEngineChecked(daemon.Options{Profile: altProf, Resolver: meshRes}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected CodeInvalidConfig when engine and resolver TLD/networkId disagree, got: %v", err)
	}

	// 2. Mismatched trust keys under identical networkId + TLD
	diffKeyRes := resolver.New(diffKeyProf, nil)
	if _, err := daemon.NewEngineChecked(daemon.Options{Profile: altProf, Resolver: diffKeyRes}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected CodeInvalidConfig when engine and resolver trust keys disagree, got: %v", err)
	}

	// 3. NewEngineWithOptions fails closed on UpsertLocalSite, IngestSignedRecords, and ServeHTTP when misconfigured
	badEng := daemon.NewEngineWithOptions(daemon.Options{Profile: altProf, Resolver: meshRes})
	if !alterrors.IsCode(badEng.InitError(), alterrors.CodeInvalidConfig) {
		t.Fatalf("expected InitError CodeInvalidConfig, got: %v", badEng.InitError())
	}
	if err := badEng.UpsertLocalSite("app.alt", config.SiteEntry{
		Routes: []config.RouteEntry{{Match: "/*", Upstream: "http://127.0.0.1:3000"}},
	}, t.TempDir()); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected UpsertLocalSite to fail closed with CodeInvalidConfig, got: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.alt/", nil)
	rec := httptest.NewRecorder()
	badEng.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("X-Alt-Error-Code") != string(alterrors.CodeInvalidConfig) {
		t.Fatalf("expected 500 INVALID_CONFIG on ServeHTTP for misconfigured engine, got %d %q",
			rec.Code, rec.Header().Get("X-Alt-Error-Code"))
	}

	// 4. Omitting opts.Profile inherits opts.Resolver's profile cleanly without disagreement
	inheritedEng, err := daemon.NewEngineChecked(daemon.Options{Resolver: meshRes})
	if err != nil {
		t.Fatalf("expected inheriting profile from resolver to succeed, got: %v", err)
	}
	if inheritedEng.Profile().NetworkID != "mesh-main-v1" || inheritedEng.Profile().TLD != "mesh" {
		t.Fatalf("unexpected inherited profile: %+v", inheritedEng.Profile())
	}

	// 5. Verify Resolver is sealed once bound to Engine (external SetClock attempts cannot bypass expiry)
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	sealedRes := resolver.NewWithConfig(resolver.Config{
		Profile: altProf,
		Clock:   func() time.Time { return now },
	})
	sealedEng, err := daemon.NewEngineChecked(daemon.Options{Profile: altProf, Resolver: sealedRes})
	if err != nil {
		t.Fatal(err)
	}
	// Attempt to rewind clock to year 2000 after Engine sealed the resolver
	sealedRes.SetClock(func() time.Time { return time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC) })

	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	_, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	_ = authPriv
	// Ingest a record that expires at 2026-11-12T11:00:00Z (expired at `now`, would be valid in year 2000)
	// Using sealedRes.Ingest directly checks sealedRes's clock (`now`), proving SetClock after Seal() was ignored.
	expCert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      "alt-main-v1",
		Domain:         "exp.alt",
		AccountID:      "acct_1",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       "2020-01-01T00:00:00Z",
		ExpiresAt:      "2026-11-12T11:00:00Z",
		IssuerKeyID:    "reg-1",
	}
	// Sign with a fresh key matching altProf so signature isn't the failure reason
	authPub2, authPriv2, _ := ed25519.GenerateKey(rand.Reader)
	prof2 := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "reg-1", PublicKey: records.FormatPublicKey(authPub2)},
		},
	}
	_ = prof2.Validate()
	res2 := resolver.NewWithConfig(resolver.Config{
		Profile: prof2,
		Clock:   func() time.Time { return now },
	})
	_, err = daemon.NewEngineChecked(daemon.Options{Profile: prof2, Resolver: res2})
	if err != nil {
		t.Fatal(err)
	}
	res2.SetClock(func() time.Time { return time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC) })

	_ = expCert.Sign(authPriv2)
	expTgt := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           "alt-main-v1",
		Domain:              "exp.alt",
		OwnershipGeneration: 1,
		Sequence:            1,
		Mode:                records.TargetModeHTTPS,
		Target:              "https://example.com",
		IssuedAt:            "2020-01-01T00:00:00Z",
		ExpiresAt:           "2027-01-01T00:00:00Z",
	}
	_ = expTgt.Sign(ownerPriv)

	if err := res2.Ingest(expCert, expTgt); !alterrors.IsCode(err, alterrors.CodeOwnershipExpired) {
		t.Fatalf("expected sealed resolver to ignore post-bind SetClock and return OWNERSHIP_EXPIRED, got: %v", err)
	}
	_ = sealedEng

	// 6. Verify Engine rejects poisoned resolvers (from invalid profile / invalid fallback key) and zero-value resolvers
	poisonedRes := resolver.New(&profile.Profile{
		Version:   99,
		NetworkID: "INVALID",
		TLD:       "../bad",
	}, nil)
	if poisonedRes.Profile() != nil {
		t.Fatalf("expected poisoned resolver Profile() to return nil, got %+v", poisonedRes.Profile())
	}
	if _, err := daemon.NewEngineChecked(daemon.Options{Resolver: poisonedRes}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected NewEngineChecked to reject poisoned resolver with CodeInvalidConfig, got: %v", err)
	}
	if _, err := daemon.NewEngineChecked(daemon.Options{Profile: altProf, Resolver: poisonedRes}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected NewEngineChecked to reject poisoned resolver even when opts.Profile is valid, got: %v", err)
	}
	if _, err := daemon.NewEngineChecked(daemon.Options{Resolver: &resolver.Resolver{}}); !alterrors.IsCode(err, alterrors.CodeInvalidConfig) {
		t.Fatalf("expected NewEngineChecked to reject uninitialized zero-value resolver, got: %v", err)
	}

	poisonedEng := daemon.NewEngineWithOptions(daemon.Options{Resolver: poisonedRes})
	if !alterrors.IsCode(poisonedEng.InitError(), alterrors.CodeInvalidConfig) || poisonedEng.Profile() != nil {
		t.Fatalf("expected NewEngineWithOptions with poisoned resolver to fail closed with nil Profile(), got err=%v prof=%+v",
			poisonedEng.InitError(), poisonedEng.Profile())
	}
	badKeyEng := daemon.NewEngine(ed25519.PublicKey([]byte("short-key")))
	if !alterrors.IsCode(badKeyEng.InitError(), alterrors.CodeInvalidConfig) {
		t.Fatalf("expected NewEngine with malformed non-empty key to fail closed with CodeInvalidConfig, got: %v", badKeyEng.InitError())
	}
}

func TestDialStaggeredEndpointsHappyEyeballsFailover(t *testing.T) {
	healthyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen healthy: %v", err)
	}
	defer healthyLn.Close()
	go func() {
		if c, aErr := healthyLn.Accept(); aErr == nil {
			_ = c.Close()
		}
	}()

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Endpoint 0 simulates a blackholed CDN/anycast VIP (blocks until ctx cancelled),
	// while Endpoint 1 connects immediately after the 80ms stagger.
	conn, err := daemon.DialStaggeredEndpoints(
		ctx,
		[]string{"blackhole:443", healthyLn.Addr().String()},
		80*time.Millisecond,
		func(dCtx context.Context, ep string) (net.Conn, error) {
			if ep == "blackhole:443" {
				<-dCtx.Done()
				return nil, dCtx.Err()
			}
			var d net.Dialer
			return d.DialContext(dCtx, "tcp", ep)
		},
	)
	if err != nil {
		t.Fatalf("DialStaggeredEndpoints failed: %v", err)
	}
	defer conn.Close()

	if elapsed := time.Since(start); elapsed > 800*time.Millisecond {
		t.Fatalf("expected Happy Eyeballs failover under 800ms, took %s", elapsed)
	}
}
