package config_test

import (
	"strings"
	"testing"

	"alt/pkg/config"
)

func TestValidConfig(t *testing.T) {
	yamlData := []byte(`
version: 1
sites:
  myproject.alt:
    routes:
      - match: /api/*
        upstream: http://localhost:8080
        stripPrefix: true
      - match: /*
        upstream: http://127.0.0.1:3000
  static.alt:
    routes:
      - match: /*
        static:
          dir: ./dist
          spaFallback: true
`)
	cfg, err := config.ParseAndValidate(yamlData)
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if len(cfg.Sites) != 2 {
		t.Fatalf("expected 2 sites, got %d", len(cfg.Sites))
	}
}

func TestInvalidConfigs(t *testing.T) {
	cases := []struct {
		name        string
		yaml        string
		errContains string
	}{
		{
			name: "duplicate keys",
			yaml: `
version: 1
sites:
  myproject.alt:
    routes:
      - match: /*
        upstream: http://localhost:3000
  myproject.alt:
    routes:
      - match: /*
        upstream: http://localhost:4000
`,
			errContains: "duplicate mapping key",
		},
		{
			name: "duplicate route match in same site",
			yaml: `
version: 1
sites:
  myproject.alt:
    routes:
      - match: /api/*
        upstream: http://localhost:3000
      - match: /api/*
        upstream: http://localhost:4000
`,
			errContains: "duplicate route match",
		},
		{
			name: "stripPrefix on root wildcard",
			yaml: `
version: 1
sites:
  myproject.alt:
    routes:
      - match: /*
        upstream: http://localhost:3000
        stripPrefix: true
`,
			errContains: "stripPrefix: true is only valid on non-root wildcard",
		},
		{
			name: "stripPrefix on static route",
			yaml: `
version: 1
sites:
  static.alt:
    routes:
      - match: /assets/*
        stripPrefix: false
        static:
          dir: ./dist
`,
			errContains: "stripPrefix cannot be set on static routes",
		},
		{
			name: "dot segment in match",
			yaml: `
version: 1
sites:
  myproject.alt:
    routes:
      - match: /api/../secret
        upstream: http://localhost:3000
`,
			errContains: "dot-segments",
		},
		{
			name: "port out of range",
			yaml: `
version: 1
sites:
  myproject.alt:
    routes:
      - match: /*
        upstream: http://localhost:70000
`,
			errContains: "port must be between 1 and 65535",
		},
		{
			name: "non-loopback upstream rejected",
			yaml: `
version: 1
sites:
  myproject.alt:
    routes:
      - match: /*
        upstream: http://192.168.1.10:3000
`,
			errContains: "explicit loopback HTTP origin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.ParseAndValidate([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.errContains)
			}
			if !strings.Contains(err.Error(), tc.errContains) {
				t.Fatalf("expected error containing %q, got: %v", tc.errContains, err)
			}
		})
	}
}

