package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapGenKeyPermissionsAndExternalDirCheck(t *testing.T) {
	// 1. Refuse keys-dir inside repository working directory
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	insideDir := filepath.Join(cwd, "bad-keys")
	if err := run(insideDir, t.TempDir(), "alt-dev-demo-v1", "alt", "register.alt", "dev-key", "https://example.org", "http://127.0.0.1:18080", 30); err == nil {
		t.Fatalf("expected error when keys-dir is inside repository")
	}

	// 2. Generate keys in external temp dir (t.TempDir is under /tmp or $TMPDIR, outside repo)
	extKeysDir := filepath.Join(t.TempDir(), "keys")
	outDir := filepath.Join(t.TempDir(), "out")
	if err := run(extKeysDir, outDir, "alt-dev-demo-v1", "alt", "register.alt", "dev-key", "https://example.org", "http://127.0.0.1:18080", 30); err != nil {
		t.Fatalf("initial bootstrap generation failed: %v", err)
	}

	// 3. Loosen existing key file permission to 0644 -> must be rejected
	authKeyPath := filepath.Join(extKeysDir, "dev-registry-authority.key")
	if err := os.Chmod(authKeyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	err = run(extKeysDir, outDir, "alt-dev-demo-v1", "alt", "register.alt", "dev-key", "https://example.org", "http://127.0.0.1:18080", 30)
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("expected insecure key file permission error, got: %v", err)
	}

	// Restore 0600 on file, loosen directory to 0755 -> must be rejected
	if err := os.Chmod(authKeyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(extKeysDir, 0o755); err != nil {
		t.Fatal(err)
	}
	err = run(extKeysDir, outDir, "alt-dev-demo-v1", "alt", "register.alt", "dev-key", "https://example.org", "http://127.0.0.1:18080", 30)
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("expected insecure directory permission error, got: %v", err)
	}
}
