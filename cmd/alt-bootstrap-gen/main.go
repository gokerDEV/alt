// Command alt-bootstrap-gen generates visibly non-production Ed25519 development keys
// OUTSIDE the repository and produces a signed content-addressed manifest + network profile
// for register.alt (or another configured domain). Private keys are written with 0600
// permissions to the specified external directory and are never printed to stdout/stderr.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"alt/pkg/names"
	"alt/pkg/profile"
	"alt/pkg/records"
	"alt/pkg/resolver"
	"gopkg.in/yaml.v3"
)

func main() {
	keysDir := flag.String("keys-dir", "", "directory OUTSIDE the repository to store 0600 Ed25519 private keys (required)")
	outDir := flag.String("out-dir", "examples/demo-bootstrap", "output directory for public manifest.json and profile.yaml")
	networkID := flag.String("network-id", profile.DemoNetworkID, "network identifier (must visibly indicate dev/demo when non-production)")
	tld := flag.String("tld", names.DefaultTLD, "private namespace TLD")
	domain := flag.String("domain", "register.alt", "bootstrap domain to sign")
	keyID := flag.String("key-id", "dev-demo-registry-2026-not-for-prod", "registry authority key identifier")
	targetURL := flag.String("target", "https://example.org", "verified HTTPS origin URL for the signed target record")
	gatewayURL := flag.String("gateway", "http://127.0.0.1:18080", "default loopback IPFS HTTP gateway URL in generated profile")
	validDays := flag.Int("valid-days", 3650, "validity window in days for the demo records")
	flag.Parse()

	if strings.TrimSpace(*keysDir) == "" {
		fmt.Fprintln(os.Stderr, "Error: --keys-dir is required and must point outside the git repository")
		os.Exit(1)
	}

	if err := run(*keysDir, *outDir, *networkID, *tld, *domain, *keyID, *targetURL, *gatewayURL, *validDays); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(keysDir, outDir, networkID, tldValue, domainInput, keyID, targetURL, gatewayURL string, validDays int) error {
	absKeys, err := filepath.Abs(keysDir)
	if err != nil {
		return err
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Safety check: refuse to write private keys inside the current repository working tree.
	if absKeys == cwd || strings.HasPrefix(absKeys, cwd+string(filepath.Separator)) {
		return fmt.Errorf("refusing to write private keys inside repository (%s); choose an external --keys-dir", absKeys)
	}

	tld, err := names.NormalizeTLD(tldValue)
	if err != nil {
		return err
	}
	fqdn, err := names.NormalizeDomain(domainInput, tld)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(absKeys, 0o700); err != nil {
		return err
	}
	dirInfo, err := os.Lstat(absKeys)
	if err != nil {
		return err
	}
	if !dirInfo.IsDir() || (dirInfo.Mode()&os.ModeSymlink) != 0 {
		return fmt.Errorf("keys-dir %s must be a real directory, not a symlink", absKeys)
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("keys-dir %s has insecure permissions %04o; run chmod 0700 first", absKeys, dirInfo.Mode().Perm())
	}

	authPub, authPriv, err := loadOrCreateEd25519Key(filepath.Join(absKeys, "dev-registry-authority.key"))
	if err != nil {
		return err
	}
	ownerPub, ownerPriv, err := loadOrCreateEd25519Key(filepath.Join(absKeys, "dev-register-owner.key"))
	if err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)
	expires := now.AddDate(0, 0, validDays)

	cert := &records.OwnershipCertificate{
		Schema:         records.SchemaOwnershipV1,
		NetworkID:      networkID,
		Domain:         fqdn,
		AccountID:      "acct_dev_demo_bootstrap",
		OwnerPublicKey: records.FormatPublicKey(ownerPub),
		Generation:     1,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      expires.Format(time.RFC3339),
		IssuerKeyID:    keyID,
	}
	if err := cert.Sign(authPriv); err != nil {
		return err
	}

	target := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           networkID,
		Domain:              fqdn,
		OwnershipGeneration: 1,
		Sequence:            1,
		Mode:                records.TargetModeHTTPS,
		Target:              targetURL,
		IssuedAt:            now.Format(time.RFC3339),
		ExpiresAt:           expires.Format(time.RFC3339),
	}
	if err := target.Sign(ownerPriv); err != nil {
		return err
	}

	ownRaw, err := json.Marshal(cert)
	if err != nil {
		return err
	}
	tgtRaw, err := json.Marshal(target)
	if err != nil {
		return err
	}

	manifest := resolver.Manifest{
		Schema:    resolver.SchemaManifestV1,
		NetworkID: networkID,
		Generated: now.Format(time.RFC3339),
		Records: map[string]resolver.ManifestEntry{
			fqdn: {
				Ownership: ownRaw,
				Target:    tgtRaw,
			},
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestCID := resolver.ComputeRawCIDv1(manifestBytes)

	prof := &profile.Profile{
		Version:   1,
		NetworkID: networkID,
		TLD:       tld,
		RegistryKeys: []profile.RegistryKey{
			{
				ID:        keyID,
				PublicKey: records.FormatPublicKey(authPub),
			},
		},
		Resolver: profile.ResolverConfig{
			ManifestCID: manifestCID,
			Gateways:    []string{gatewayURL},
		},
		ReservedNames: []string{"register"},
		Branding:      profile.BrandingConfig{Name: "ALT Development Demo (Non-Production)"},
	}
	if err := prof.Validate(); err != nil {
		return err
	}

	// Verify generated bundle end-to-end before writing
	res, err := resolver.NewChecked(resolver.Config{
		Profile: prof,
		Source:  resolver.NewFixtureSource(manifestBytes, manifestCID, networkID),
	})
	if err != nil {
		return err
	}
	if _, err := res.Resolve(context.Background(), fqdn); err != nil {
		return fmt.Errorf("self-verification failed: %w", err)
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	manifestPath := filepath.Join(outDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		return err
	}

	profYAML, err := yaml.Marshal(prof)
	if err != nil {
		return err
	}
	header := "# NON-PRODUCTION DEVELOPMENT DEMO PROFILE\n# Generated by cmd/alt-bootstrap-gen. Contains ONLY public keys and content-addressed CID.\n"
	profilePath := filepath.Join(outDir, "profile.yaml")
	if err := os.WriteFile(profilePath, append([]byte(header), profYAML...), 0o644); err != nil {
		return err
	}

	fmt.Printf("Generated public bootstrap artifacts:\n")
	fmt.Printf("  Network ID:         %s\n", prof.NetworkID)
	fmt.Printf("  Domain:             %s\n", fqdn)
	fmt.Printf("  Authority Key ID:   %s\n", keyID)
	fmt.Printf("  Authority PubKey:   %s\n", records.FormatPublicKey(authPub))
	fmt.Printf("  Owner PubKey:       %s\n", records.FormatPublicKey(ownerPub))
	fmt.Printf("  Manifest CIDv1:     %s\n", manifestCID)
	fmt.Printf("  Public Manifest:    %s\n", manifestPath)
	fmt.Printf("  Public Profile:     %s\n", profilePath)
	return nil
}

func loadOrCreateEd25519Key(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("refusing non-regular key file %s (symlinks/devices disallowed)", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, nil, fmt.Errorf("refusing private key %s with insecure permissions %04o (must not be group/world accessible)", path, info.Mode().Perm())
		}
		rawB64, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		seedOrPriv, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawB64)))
		if err != nil {
			return nil, nil, fmt.Errorf("decode key %s: %w", path, err)
		}
		if len(seedOrPriv) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(seedOrPriv)
			return priv.Public().(ed25519.PublicKey), priv, nil
		}
		return nil, nil, fmt.Errorf("unexpected private key size in %s", path)
	} else if !os.IsNotExist(statErr) {
		return nil, nil, statErr
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(priv) + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if _, err := f.Write([]byte(encoded)); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if err := f.Close(); err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}
