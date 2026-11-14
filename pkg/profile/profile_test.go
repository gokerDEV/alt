package profile_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"alt/pkg/profile"
)

func TestParseAndValidateProfile(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encodedKey := "ed25519:" + base64.StdEncoding.EncodeToString(pub)

	rawYAML := `
version: 1
networkId: example-mesh-v1
tld: mesh
registryKeys:
  - id: registry-2026
    publicKey: ` + encodedKey + `
resolver:
  ipnsRoot: k51qzi5uqu5dlvj2baxnqndepeb86cbk3ng7n3i46uzyxzyqj2xjonzllnv0v8
  gateways:
    - https://ipfs.example.invalid
    - http://127.0.0.1:8080
reservedNames:
  - register
branding:
  name: Example Mesh
`

	p, err := profile.ParseAndValidate([]byte(rawYAML))
	if err != nil {
		t.Fatalf("expected valid profile, got error: %v", err)
	}
	if p.NetworkID != "example-mesh-v1" || p.TLD != "mesh" {
		t.Fatalf("unexpected networkId/tld: %s / %s", p.NetworkID, p.TLD)
	}
	if _, ok := p.AuthorityKey("registry-2026"); !ok {
		t.Fatalf("expected registry-2026 key to be loaded")
	}
	if !p.IsReserved("register") || !p.IsReserved("register.mesh") {
		t.Fatalf("expected register.mesh to be reserved")
	}
	if p.IsReserved("app.mesh") {
		t.Fatalf("did not expect app.mesh to be reserved")
	}

	// Verify AuthorityKey returns an isolated slice so caller mutation cannot corrupt the trust root
	gotKey, ok := p.AuthorityKey("registry-2026")
	if !ok {
		t.Fatal("expected registry-2026 key")
	}
	gotKey[0] ^= 0xff
	gotKeyAgain, _ := p.AuthorityKey("registry-2026")
	if gotKeyAgain[0] != pub[0] {
		t.Fatalf("mutating slice returned by AuthorityKey corrupted profile trust key")
	}
}

func TestRejectInvalidProfiles(t *testing.T) {
	cases := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name: "non-loopback http gateway",
			yaml: `
version: 1
networkId: alt-main-v1
tld: alt
resolver:
  gateways:
    - http://gateway.example.com
`,
			errContains: "plaintext http:// gateway is only allowed on loopback",
		},
		{
			name: "unknown field",
			yaml: `
version: 1
networkId: alt-main-v1
tld: alt
extraField: true
`,
			errContains: "schema error",
		},
		{
			name: "duplicate key",
			yaml: `
version: 1
networkId: alt-main-v1
networkId: other-v1
tld: alt
`,
			errContains: "duplicate mapping key",
		},
		{
			name: "invalid networkId",
			yaml: `
version: 1
networkId: BAD_UPPERCASE
tld: alt
`,
			errContains: "networkId",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := profile.ParseAndValidate([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tc.errContains, err)
			}
		})
	}
}

func TestSignedProfileBundleRotationAndPersistence(t *testing.T) {
	oldPub, oldPriv, _ := ed25519.GenerateKey(rand.Reader)
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)

	oldKeyStr := "ed25519:" + base64.StdEncoding.EncodeToString(oldPub)
	newKeyStr := "ed25519:" + base64.StdEncoding.EncodeToString(newPub)

	current := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "registry-2026", PublicKey: oldKeyStr},
		},
	}
	if err := current.Validate(); err != nil {
		t.Fatal(err)
	}

	next := current.Clone()
	next.RegistryKeys = append(next.RegistryKeys, profile.RegistryKey{
		ID:        "registry-2027",
		PublicKey: newKeyStr,
	})

	bundle := &profile.SignedProfileBundle{
		Schema:      profile.SchemaProfileBundleV1,
		NetworkID:   "alt-main-v1",
		Sequence:    2,
		IssuedAt:    "2026-11-10T00:00:00Z",
		ExpiresAt:   "2027-11-10T00:00:00Z",
		SignerKeyID: "registry-2026",
		Profile:     *next,
	}
	if err := bundle.Sign(oldPriv); err != nil {
		t.Fatalf("Sign bundle: %v", err)
	}

	verified, err := bundle.Verify(current, bundleTime(t, "2026-11-14T00:00:00Z"))
	if err != nil {
		t.Fatalf("Verify bundle: %v", err)
	}
	if _, ok := verified.AuthorityKey("registry-2027"); !ok {
		t.Fatalf("expected rotated key registry-2027 in verified profile")
	}

	tmp := t.TempDir()
	if err := profile.SavePinnedProfile(tmp, verified); err != nil {
		t.Fatalf("SavePinnedProfile: %v", err)
	}
	loaded, err := profile.LoadPinnedOrOfficial(tmp)
	if err != nil {
		t.Fatalf("LoadPinnedOrOfficial: %v", err)
	}
	if _, ok := loaded.AuthorityKey("registry-2027"); !ok {
		t.Fatalf("expected persisted profile to include registry-2027")
	}

	// Verify ApplySignedBundleToStateDir enforces monotonic bundle sequence against rollback
	applyDir := t.TempDir()
	if _, err := profile.ApplySignedBundleToStateDir(applyDir, current, bundle, bundleTime(t, "2026-11-14T00:00:00Z")); err != nil {
		t.Fatalf("ApplySignedBundleToStateDir(seq=2): %v", err)
	}
	if _, err := profile.ApplySignedBundleToStateDir(applyDir, loaded, bundle, bundleTime(t, "2026-11-14T00:00:00Z")); err == nil {
		t.Fatalf("expected duplicate/rollback bundle sequence=2 to be rejected")
	}
}

func bundleTime(t *testing.T, s string) (out time.Time) {
	t.Helper()
	var err error
	out, err = time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
