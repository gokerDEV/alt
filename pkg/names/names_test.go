package names_test

import (
	"testing"

	"alt/pkg/names"
)

func TestConfigurableNamespace(t *testing.T) {
	for _, tc := range []struct {
		input string
		tld   string
		want  string
	}{
		{"local", "alt", "local.alt"},
		{"Blog.MESH.", ".mesh", "blog.mesh"},
	} {
		got, err := names.NormalizeDomain(tc.input, tc.tld)
		if err != nil || got != tc.want {
			t.Fatalf("NormalizeDomain(%q, %q) = %q, %v; want %q", tc.input, tc.tld, got, err, tc.want)
		}
	}

	for _, invalid := range []string{"two.labels.alt", "-bad.alt", "bad_.alt"} {
		if _, err := names.NormalizeDomain(invalid, names.DefaultTLD); err == nil {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}
