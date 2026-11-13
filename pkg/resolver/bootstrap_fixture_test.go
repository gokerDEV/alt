package resolver_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alt/pkg/profile"
	"alt/pkg/resolver"
)

func TestCommittedDemoBootstrapFixture(t *testing.T) {
	profilePath := filepath.Join("..", "..", "examples", "demo-bootstrap", "profile.yaml")
	manifestPath := filepath.Join("..", "..", "examples", "demo-bootstrap", "manifest.json")

	prof, err := profile.LoadFile(profilePath)
	if err != nil {
		t.Fatalf("load demo profile.yaml: %v", err)
	}
	if prof.NetworkID != profile.DemoNetworkID {
		t.Fatalf("expected demo networkId %q, got %q", profile.DemoNetworkID, prof.NetworkID)
	}

	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read demo manifest.json: %v", err)
	}
	computedCID := resolver.ComputeRawCIDv1(rawManifest)
	if computedCID != prof.Resolver.ManifestCID {
		t.Fatalf("manifest CID mismatch: profile has %q, computed %q", prof.Resolver.ManifestCID, computedCID)
	}

	src := resolver.NewFixtureSource(rawManifest, prof.Resolver.ManifestCID, prof.NetworkID)
	res := resolver.New(prof, src)
	res.SetClock(func() time.Time { return time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC) })

	out, err := res.Resolve(context.Background(), "register.alt")
	if err != nil {
		t.Fatalf("failed to resolve register.alt from committed bootstrap fixture: %v", err)
	}
	if out.Target.Target != "https://example.org" {
		t.Fatalf("expected demo target https://example.org, got %q", out.Target.Target)
	}
}
