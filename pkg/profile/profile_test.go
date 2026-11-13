package profile_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

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
