package daemon_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alt/pkg/config"
	"alt/pkg/daemon"
	"alt/pkg/profile"
	"alt/pkg/resolver"
)

func TestDaemonStateStoreAndIPCRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	stateFile := filepath.Join(tmp, "daemon-state.json")

	store, err := daemon.OpenDaemonStateStore(stateFile, "alt-main-v1", "alt")
	if err != nil {
		t.Fatalf("OpenDaemonStateStore: %v", err)
	}

	lock, err := daemon.AcquireInstanceLock(tmp, "alt-main-v1", "")
	if err != nil {
		t.Fatalf("AcquireInstanceLock: %v", err)
	}
	defer lock.Release()

	// Second lock on same directory must fail with ErrDaemonAlreadyRunning.
	if _, err := daemon.AcquireInstanceLock(tmp, "alt-main-v1", ""); err == nil {
		t.Fatalf("expected second AcquireInstanceLock to fail")
	}

	prof := profile.Official()
	resStore, err := resolver.OpenStateStore(filepath.Join(tmp, "resolver-state.json"), prof.NetworkID)
	if err != nil {
		t.Fatalf("OpenStateStore: %v", err)
	}
	res, err := resolver.NewChecked(resolver.Config{
		Profile:    prof,
		StateStore: resStore,
	})
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	eng, err := daemon.NewEngineChecked(daemon.Options{
		Profile:  prof,
		Resolver: res,
	})
	if err != nil {
		t.Fatalf("NewEngineChecked: %v", err)
	}

	ipcSrv, err := daemon.StartIPCServer(daemon.IPCServerConfig{
		Engine:     eng,
		StateStore: store,
		StateDir:   tmp,
		StartedAt:  time.Now().Add(-5 * time.Second),
		Version:    "test-1.0.0",
		HTTPSAddr:  "127.0.0.1:8443",
		DNSAddr:    "127.0.0.1:15353",
		LoopbackIP: "127.0.0.2",
	})
	if err != nil {
		t.Fatalf("StartIPCServer: %v", err)
	}
	defer ipcSrv.Close()

	client, err := daemon.NewIPCClient(tmp)
	if err != nil {
		t.Fatalf("NewIPCClient: %v", err)
	}

	ctx := context.Background()
	if err := client.Health(ctx); err != nil {
		t.Fatalf("Health: %v", err)
	}

	// Upsert a local dev override via IPC
	upsertResp, err := client.DevUpsert(ctx, daemon.IPCDevUpsertRequest{
		Overrides: []daemon.PersistedSiteOverride{
			{
				Domain:     "app.alt",
				SourceMode: "port",
				BaseDir:    tmp,
				Entry: config.SiteEntry{
					Routes: []config.RouteEntry{
						{Match: "/*", Upstream: "http://127.0.0.1:3000"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("DevUpsert: %v", err)
	}
	if len(upsertResp.Activated) != 1 || upsertResp.Activated[0].Domain != "app.alt" {
		t.Fatalf("unexpected DevUpsert response: %+v", upsertResp)
	}

	// Verify status and list via IPC
	st, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Version != "test-1.0.0" || len(st.Sites) != 1 || !st.Resolver.PersistentBacked {
		t.Fatalf("unexpected Status: %+v", st)
	}

	listResp, err := client.ListSites(ctx)
	if err != nil {
		t.Fatalf("ListSites: %v", err)
	}
	if len(listResp.Sites) != 1 || listResp.Sites[0].Domain != "app.alt" {
		t.Fatalf("unexpected ListSites: %+v", listResp)
	}

	// Verify persistence across daemon restart
	_ = ipcSrv.Close()
	reopenedStore, err := daemon.OpenDaemonStateStore(stateFile, "alt-main-v1", "alt")
	if err != nil {
		t.Fatalf("reopen DaemonStateStore: %v", err)
	}
	eng2, err := daemon.NewEngineChecked(daemon.Options{Profile: prof})
	if err != nil {
		t.Fatalf("NewEngineChecked 2: %v", err)
	}
	if err := daemon.RestoreSitesIntoEngine(eng2, reopenedStore); err != nil {
		t.Fatalf("RestoreSitesIntoEngine: %v", err)
	}
	if len(eng2.ListLocalSites()) != 1 || eng2.ListLocalSites()[0] != "app.alt" {
		t.Fatalf("expected app.alt restored into engine, got %v", eng2.ListLocalSites())
	}

	// Verify RotatingLogWriter rotates files cleanly
	logPath := filepath.Join(tmp, "logs", "daemon.log")
	lw, err := daemon.NewRotatingLogWriter(logPath, 64, 2)
	if err != nil {
		t.Fatalf("NewRotatingLogWriter: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := lw.Write([]byte("0123456789abcdef0123456789abcdef\n")); err != nil {
			t.Fatalf("log Write: %v", err)
		}
	}
	_ = lw.Close()
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("expected rotated backup %s.1 to exist: %v", logPath, err)
	}
}
