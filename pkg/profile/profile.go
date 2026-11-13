// Package profile defines the versioned network profile schema, strict loader,
// and default .alt profile used to configure an independent ALT-compatible namespace.
package profile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"

	"alt/pkg/names"
	"gopkg.in/yaml.v3"
)

const (
	// DefaultNetworkID is the official .alt network identifier.
	DefaultNetworkID = "alt-main-v1"

	// DemoNetworkID is the visibly non-production network identifier for the local/IPFS demo slice.
	DemoNetworkID = "alt-dev-demo-v1"

	ed25519Prefix = "ed25519:"
)

var (
	networkIDPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])$`)
	keyIDPattern     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	cidRefPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{10,256}$`)
)

// ValidationError reports a network profile schema or semantic violation.
type ValidationError struct {
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("profile: %s", e.Message)
	}
	return fmt.Sprintf("profile (%s): %s", e.Path, e.Message)
}

// RegistryKey binds a key identifier to an Ed25519 public key ("ed25519:<base64>").
type RegistryKey struct {
	ID        string `yaml:"id" json:"id"`
	PublicKey string `yaml:"publicKey" json:"publicKey"`
}

// ResolverConfig configures untrusted transport pointers (manifest CID or IPNS root and HTTP gateways).
type ResolverConfig struct {
	ManifestCID string   `yaml:"manifestCid,omitempty" json:"manifestCid,omitempty"`
	IPNSRoot    string   `yaml:"ipnsRoot,omitempty" json:"ipnsRoot,omitempty"`
	Gateways    []string `yaml:"gateways,omitempty" json:"gateways,omitempty"`
}

// BrandingConfig allows downstream networks to customize display branding.
type BrandingConfig struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
}

// Profile represents a versioned network profile (ARCHITECTURE.md §3, PLAN.md §3.B).
type Profile struct {
	Version       int            `yaml:"version" json:"version"`
	NetworkID     string         `yaml:"networkId" json:"networkId"`
	TLD           string         `yaml:"tld" json:"tld"`
	RegistryKeys  []RegistryKey  `yaml:"registryKeys,omitempty" json:"registryKeys,omitempty"`
	Resolver      ResolverConfig `yaml:"resolver,omitempty" json:"resolver,omitempty"`
	ReservedNames []string       `yaml:"reservedNames,omitempty" json:"reservedNames,omitempty"`
	Branding      BrandingConfig `yaml:"branding,omitempty" json:"branding,omitempty"`

	parsedKeys map[string]ed25519.PublicKey
}

// Default returns the default .alt network profile for local-first operation.
func Default() *Profile {
	p := &Profile{
		Version:       1,
		NetworkID:     DefaultNetworkID,
		TLD:           names.DefaultTLD,
		ReservedNames: []string{"register"},
		Branding:      BrandingConfig{Name: "ALT"},
		parsedKeys:    make(map[string]ed25519.PublicKey),
	}
	return p
}

// ForLocalTLD constructs a minimal local-first network profile for a custom TLD when no profile file is provided.
func ForLocalTLD(tldValue string) (*Profile, error) {
	tld, err := names.NormalizeTLD(tldValue)
	if err != nil {
		return nil, err
	}
	if tld == names.DefaultTLD {
		return Default(), nil
	}
	p := &Profile{
		Version:       1,
		NetworkID:     tld + "-local-v1",
		TLD:           tld,
		ReservedNames: []string{"register"},
		Branding:      BrandingConfig{Name: strings.ToUpper(tld)},
		parsedKeys:    make(map[string]ed25519.PublicKey),
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadFile reads, parses, and strictly validates a network profile YAML file.
func LoadFile(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAndValidate(data)
}

// ParseAndValidate parses YAML bytes with strict AST checks (no duplicate keys, aliases,
// merge keys, custom tags, or unknown fields) and validates all network profile invariants.
func ParseAndValidate(data []byte) (*Profile, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &ValidationError{Message: "empty YAML document"}
		}
		return nil, &ValidationError{Message: fmt.Sprintf("YAML syntax error: %v", err)}
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &ValidationError{Message: "multiple YAML documents are not allowed"}
	}

	if err := checkASTNode(&doc, ""); err != nil {
		return nil, err
	}

	strictDec := yaml.NewDecoder(bytes.NewReader(data))
	strictDec.KnownFields(true)
	var p Profile
	if err := strictDec.Decode(&p); err != nil {
		return nil, &ValidationError{Message: fmt.Sprintf("schema error: %v", err)}
	}

	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks all network profile fields, normalizes TLD and reserved names, and caches parsed keys.
func (p *Profile) Validate() error {
	if p.Version != 1 {
		return &ValidationError{Path: "version", Message: "version must be 1"}
	}
	if !networkIDPattern.MatchString(p.NetworkID) {
		return &ValidationError{
			Path:    "networkId",
			Message: "networkId must be 3-63 lowercase ASCII alphanumeric characters or hyphens",
		}
	}

	tld, err := names.NormalizeTLD(p.TLD)
	if err != nil {
		return &ValidationError{Path: "tld", Message: err.Error()}
	}
	p.TLD = tld

	parsedKeys := make(map[string]ed25519.PublicKey, len(p.RegistryKeys))
	for idx, rk := range p.RegistryKeys {
		fieldPath := fmt.Sprintf("registryKeys[%d]", idx)
		if !keyIDPattern.MatchString(rk.ID) {
			return &ValidationError{Path: fieldPath + ".id", Message: "invalid key id"}
		}
		if _, dup := parsedKeys[rk.ID]; dup {
			return &ValidationError{Path: fieldPath + ".id", Message: fmt.Sprintf("duplicate registry key id %q", rk.ID)}
		}
		pub, err := parseEd25519PublicKey(rk.PublicKey)
		if err != nil {
			return &ValidationError{Path: fieldPath + ".publicKey", Message: err.Error()}
		}
		parsedKeys[rk.ID] = pub
	}
	p.parsedKeys = parsedKeys

	if p.Resolver.ManifestCID != "" && !cidRefPattern.MatchString(p.Resolver.ManifestCID) {
		return &ValidationError{Path: "resolver.manifestCid", Message: "invalid manifestCid format"}
	}
	if p.Resolver.IPNSRoot != "" && !cidRefPattern.MatchString(p.Resolver.IPNSRoot) {
		return &ValidationError{Path: "resolver.ipnsRoot", Message: "invalid ipnsRoot format"}
	}
	for idx, gw := range p.Resolver.Gateways {
		gwPath := fmt.Sprintf("resolver.gateways[%d]", idx)
		u, err := url.Parse(gw)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return &ValidationError{Path: gwPath, Message: "gateway must be a valid http:// or https:// base URL"}
		}
		if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
			return &ValidationError{Path: gwPath, Message: "plaintext http:// gateway is only allowed on loopback addresses"}
		}
	}

	seenReserved := make(map[string]struct{}, len(p.ReservedNames))
	normalizedReserved := make([]string, 0, len(p.ReservedNames))
	for idx, rName := range p.ReservedNames {
		rPath := fmt.Sprintf("reservedNames[%d]", idx)
		fqdn, err := names.NormalizeDomain(rName, p.TLD)
		if err != nil {
			return &ValidationError{Path: rPath, Message: fmt.Sprintf("invalid reserved name %q: %v", rName, err)}
		}
		label := strings.TrimSuffix(fqdn, "."+p.TLD)
		if _, dup := seenReserved[label]; dup {
			return &ValidationError{Path: rPath, Message: fmt.Sprintf("duplicate reserved name %q", label)}
		}
		seenReserved[label] = struct{}{}
		normalizedReserved = append(normalizedReserved, label)
	}
	p.ReservedNames = normalizedReserved
	return nil
}

// AuthorityKey looks up a trusted registry authority Ed25519 public key by key ID.
// It returns a fresh copy of the key slice so callers cannot mutate the profile's trust store.
func (p *Profile) AuthorityKey(keyID string) (ed25519.PublicKey, bool) {
	if p == nil || p.parsedKeys == nil {
		return nil, false
	}
	pub, ok := p.parsedKeys[keyID]
	if !ok {
		return nil, false
	}
	return append(ed25519.PublicKey(nil), pub...), true
}

// EqualTrustAndNamespace reports whether two validated profiles share the exact same
// networkId, TLD, and registry authority trust keys (IDs and public key bytes).
func (p *Profile) EqualTrustAndNamespace(other *Profile) bool {
	if p == nil || other == nil {
		return p == other
	}
	if p.Version != other.Version || p.NetworkID != other.NetworkID || p.TLD != other.TLD {
		return false
	}
	if len(p.parsedKeys) != len(other.parsedKeys) {
		return false
	}
	for id, pub := range p.parsedKeys {
		otherPub, ok := other.parsedKeys[id]
		if !ok || !bytes.Equal(pub, otherPub) {
			return false
		}
	}
	return true
}

// AuthorityKeys returns a copy of the map of key ID to Ed25519 public key.
func (p *Profile) AuthorityKeys() map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(p.parsedKeys))
	for id, k := range p.parsedKeys {
		out[id] = append(ed25519.PublicKey(nil), k...)
	}
	return out
}

// Clone returns a deep copy of the Profile so callers cannot mutate shared trust roots.
func (p *Profile) Clone() *Profile {
	if p == nil {
		return nil
	}
	cp := *p
	if p.RegistryKeys != nil {
		cp.RegistryKeys = append([]RegistryKey(nil), p.RegistryKeys...)
	}
	if p.Resolver.Gateways != nil {
		cp.Resolver.Gateways = append([]string(nil), p.Resolver.Gateways...)
	}
	if p.ReservedNames != nil {
		cp.ReservedNames = append([]string(nil), p.ReservedNames...)
	}
	cp.parsedKeys = make(map[string]ed25519.PublicKey, len(p.parsedKeys))
	for id, k := range p.parsedKeys {
		cp.parsedKeys[id] = append(ed25519.PublicKey(nil), k...)
	}
	return &cp
}

// IsReserved reports whether a domain or label is reserved in this network profile.
func (p *Profile) IsReserved(domainOrLabel string) bool {
	if p == nil {
		return false
	}
	fqdn, err := names.NormalizeDomain(domainOrLabel, p.TLD)
	if err != nil {
		return false
	}
	label := strings.TrimSuffix(fqdn, "."+p.TLD)
	for _, r := range p.ReservedNames {
		if r == label {
			return true
		}
	}
	return false
}

func parseEd25519PublicKey(encoded string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(encoded, ed25519Prefix) {
		return nil, errors.New("public key must have prefix 'ed25519:'")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encoded, ed25519Prefix))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("invalid base64 ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if host == "127.0.0.1" || host == "::1" {
		return true
	}
	return strings.HasPrefix(host, "127.")
}

var allowedStandardTags = map[string]bool{
	"!!map":   true,
	"!!seq":   true,
	"!!str":   true,
	"!!int":   true,
	"!!bool":  true,
	"!!float": true,
	"!!null":  true,
}

func checkASTNode(node *yaml.Node, path string) error {
	if node == nil {
		return nil
	}
	if node.Anchor != "" {
		return &ValidationError{Path: path, Message: fmt.Sprintf("YAML anchors (&%s) are not allowed", node.Anchor)}
	}
	if node.Kind == yaml.AliasNode {
		return &ValidationError{Path: path, Message: "YAML aliases (*) are not allowed"}
	}
	if node.Tag != "" && !allowedStandardTags[node.Tag] {
		if node.Tag == "!!merge" {
			return &ValidationError{Path: path, Message: "YAML merge keys (<<) are not allowed"}
		}
		return &ValidationError{Path: path, Message: fmt.Sprintf("custom YAML tag %q is not allowed", node.Tag)}
	}

	switch node.Kind {
	case yaml.DocumentNode:
		for _, child := range node.Content {
			if err := checkASTNode(child, path); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			kNode := node.Content[i]
			vNode := node.Content[i+1]
			if kNode.Tag == "!!merge" || kNode.Value == "<<" {
				return &ValidationError{Path: path, Message: "YAML merge keys (<<) are not allowed"}
			}
			key := kNode.Value
			if _, exists := seen[key]; exists {
				return &ValidationError{Path: joinPath(path, key), Message: "duplicate mapping key"}
			}
			seen[key] = struct{}{}
			if err := checkASTNode(vNode, joinPath(path, key)); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for idx, child := range node.Content {
			if err := checkASTNode(child, fmt.Sprintf("%s[%d]", path, idx)); err != nil {
				return err
			}
		}
	}
	return nil
}

func joinPath(base, elem string) string {
	if base == "" {
		return elem
	}
	return base + "." + elem
}
