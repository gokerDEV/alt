// Package names defines the DNS namespace policy used by an ALT-compatible network.
package names

import (
	"fmt"
	"regexp"
	"strings"
)

const DefaultTLD = "alt"

var labelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// NormalizeTLD returns a lowercase TLD without a leading dot.
func NormalizeTLD(value string) (string, error) {
	tld := strings.ToLower(strings.TrimSpace(value))
	tld = strings.TrimPrefix(tld, ".")
	if !labelPattern.MatchString(tld) {
		return "", fmt.Errorf("names: invalid TLD %q", value)
	}
	return tld, nil
}

// NormalizeDomain normalizes a single-label name in the selected namespace.
// A short name is expanded with the configured TLD.
func NormalizeDomain(value, tldValue string) (string, error) {
	tld, err := NormalizeTLD(tldValue)
	if err != nil {
		return "", err
	}

	domain := strings.ToLower(strings.TrimSpace(value))
	domain = strings.TrimSuffix(domain, ".")
	if !strings.Contains(domain, ".") {
		domain += "." + tld
	}

	label, ok := strings.CutSuffix(domain, "."+tld)
	if !ok || !labelPattern.MatchString(label) {
		return "", fmt.Errorf("names: domain must be a single lowercase DNS label under .%s", tld)
	}
	return domain, nil
}

// IsDomain reports whether value is canonical for the selected namespace.
func IsDomain(value, tld string) bool {
	normalized, err := NormalizeDomain(value, tld)
	return err == nil && normalized == value
}

// Contains reports whether a DNS name is the namespace apex or is below it.
func Contains(value, tldValue string) bool {
	tld, err := NormalizeTLD(tldValue)
	if err != nil {
		return false
	}
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	return name == tld || strings.HasSuffix(name, "."+tld)
}
