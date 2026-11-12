package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"alt/pkg/names"
	"gopkg.in/yaml.v3"
)

var (
	matchRegex    = regexp.MustCompile(`^/(?:[A-Za-z0-9._~-]+/)*(?:[A-Za-z0-9._~-]+|\*)?$`)
	upstreamRegex = regexp.MustCompile(`^http://(?:localhost|127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$`)
)

// Config represents the validated alt.yaml v1 specification (§18).
type Config struct {
	Version int                  `yaml:"version" json:"version"`
	Sites   map[string]SiteEntry `yaml:"sites" json:"sites"`
}

// SiteEntry holds the route definitions for a single .alt domain.
type SiteEntry struct {
	Routes []RouteEntry `yaml:"routes" json:"routes"`
}

// ValidateRoutes checks all routes within the SiteEntry.
func (s *SiteEntry) ValidateRoutes() error {
	if len(s.Routes) == 0 {
		return &ValidationError{Path: "routes", Message: "at least one route must be defined"}
	}
	seenMatches := make(map[string]struct{}, len(s.Routes))
	for idx, route := range s.Routes {
		routePath := fmt.Sprintf("routes[%d]", idx)
		if err := validateRoute(route, routePath, seenMatches); err != nil {
			return err
		}
	}
	return nil
}

// RouteEntry defines either a loopback upstream proxy route or a static directory route.
type RouteEntry struct {
	Match       string       `yaml:"match" json:"match"`
	Upstream    string       `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	StripPrefix *bool        `yaml:"stripPrefix,omitempty" json:"stripPrefix,omitempty"`
	Static      *StaticEntry `yaml:"static,omitempty" json:"static,omitempty"`
}

// ShouldStripPrefix returns the effective boolean value of StripPrefix (defaults to false).
func (r RouteEntry) ShouldStripPrefix() bool {
	return r.StripPrefix != nil && *r.StripPrefix
}

// StaticEntry defines static directory serving options.
type StaticEntry struct {
	Dir         string `yaml:"dir" json:"dir"`
	SPAFallback bool   `yaml:"spaFallback,omitempty" json:"spaFallback,omitempty"`
}

// ValidationError reports a schema or semantic violation with its exact field path.
type ValidationError struct {
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("config: %s", e.Message)
	}
	return fmt.Sprintf("config (%s): %s", e.Path, e.Message)
}

// LoadFile reads, parses, and strictly validates an alt.yaml file from disk.
func LoadFile(path string) (*Config, error) {
	return LoadFileForTLD(path, names.DefaultTLD)
}

// LoadFileForTLD reads and validates a config for the selected namespace.
func LoadFileForTLD(path, tld string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAndValidateForTLD(data, tld)
}

// ParseAndValidate parses YAML bytes as a single document with strict AST checks
// (no duplicate keys, aliases, merge keys, custom tags, or unknown fields) and
// runs all §18 semantic rules.
func ParseAndValidate(data []byte) (*Config, error) {
	return ParseAndValidateForTLD(data, names.DefaultTLD)
}

// ParseAndValidateForTLD parses and validates YAML for the selected namespace.
func ParseAndValidateForTLD(data []byte, tld string) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, &ValidationError{Message: "empty YAML document"}
		}
		return nil, &ValidationError{Message: fmt.Sprintf("YAML syntax error: %v", err)}
	}

	// Ensure single document
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, &ValidationError{Message: "multiple YAML documents are not allowed"}
	}

	if err := checkASTNode(&doc, ""); err != nil {
		return nil, err
	}

	strictDec := yaml.NewDecoder(bytes.NewReader(data))
	strictDec.KnownFields(true)
	var cfg Config
	if err := strictDec.Decode(&cfg); err != nil {
		return nil, &ValidationError{Message: fmt.Sprintf("schema error: %v", err)}
	}

	if err := cfg.ValidateForTLD(tld); err != nil {
		return nil, err
	}
	return &cfg, nil
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
			childPath := joinPath(path, key)
			if err := checkASTNode(vNode, childPath); err != nil {
				return err
			}
		}
	case yaml.SequenceNode:
		for idx, child := range node.Content {
			childPath := fmt.Sprintf("%s[%d]", path, idx)
			if err := checkASTNode(child, childPath); err != nil {
				return err
			}
		}
	}
	return nil
}

// Validate checks all §18 semantic invariants on a Config struct.
func (c *Config) Validate() error {
	return c.ValidateForTLD(names.DefaultTLD)
}

// ValidateForTLD checks all config invariants for the selected namespace.
func (c *Config) ValidateForTLD(tldValue string) error {
	tld, err := names.NormalizeTLD(tldValue)
	if err != nil {
		return &ValidationError{Path: "sites", Message: err.Error()}
	}
	if c.Version != 1 {
		return &ValidationError{Path: "version", Message: "version must be 1"}
	}
	if len(c.Sites) == 0 {
		return &ValidationError{Path: "sites", Message: "at least one site must be defined"}
	}

	for domain, site := range c.Sites {
		sitePath := joinPath("sites", domain)
		if !names.IsDomain(domain, tld) {
			return &ValidationError{
				Path:    sitePath,
				Message: fmt.Sprintf("domain must be a lowercase single-label ASCII name under .%s", tld),
			}
		}
		if len(site.Routes) == 0 {
			return &ValidationError{
				Path:    joinPath(sitePath, "routes"),
				Message: "at least one route must be defined",
			}
		}

		seenMatches := make(map[string]struct{}, len(site.Routes))
		for idx, route := range site.Routes {
			routePath := fmt.Sprintf("%s.routes[%d]", sitePath, idx)
			if err := validateRoute(route, routePath, seenMatches); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateRoute(r RouteEntry, routePath string, seenMatches map[string]struct{}) error {
	if err := validateMatchPattern(r.Match, joinPath(routePath, "match")); err != nil {
		return err
	}
	if _, duplicate := seenMatches[r.Match]; duplicate {
		return &ValidationError{
			Path:    joinPath(routePath, "match"),
			Message: fmt.Sprintf("duplicate route match %q in the same site", r.Match),
		}
	}
	seenMatches[r.Match] = struct{}{}

	hasUpstream := r.Upstream != ""
	hasStatic := r.Static != nil

	if hasUpstream == hasStatic {
		return &ValidationError{
			Path:    routePath,
			Message: "route must specify either 'upstream' or 'static', never both or neither",
		}
	}

	if hasUpstream {
		if err := validateUpstream(r.Upstream, joinPath(routePath, "upstream")); err != nil {
			return err
		}
		if r.ShouldStripPrefix() {
			if r.Match == "/*" || !strings.HasSuffix(r.Match, "/*") {
				return &ValidationError{
					Path:    joinPath(routePath, "stripPrefix"),
					Message: "stripPrefix: true is only valid on non-root wildcard proxy routes (e.g., /api/*)",
				}
			}
		}
	}

	if hasStatic {
		if r.StripPrefix != nil {
			return &ValidationError{
				Path:    joinPath(routePath, "stripPrefix"),
				Message: "stripPrefix cannot be set on static routes",
			}
		}
		if strings.TrimSpace(r.Static.Dir) == "" {
			return &ValidationError{
				Path:    joinPath(routePath, "static.dir"),
				Message: "static dir must not be empty",
			}
		}
	}

	return nil
}

func validateMatchPattern(match, fieldPath string) error {
	if match == "" {
		return &ValidationError{Path: fieldPath, Message: "match is required"}
	}
	if !matchRegex.MatchString(match) {
		return &ValidationError{
			Path:    fieldPath,
			Message: fmt.Sprintf("invalid match pattern %q", match),
		}
	}
	if match != "/" && strings.HasSuffix(match, "/") {
		return &ValidationError{
			Path:    fieldPath,
			Message: "trailing slash is not allowed except for root '/'",
		}
	}
	segments := strings.Split(strings.TrimPrefix(match, "/"), "/")
	for _, seg := range segments {
		if seg == "." || seg == ".." {
			return &ValidationError{
				Path:    fieldPath,
				Message: "dot-segments ('.' or '..') are not allowed in route match patterns",
			}
		}
	}
	return nil
}

func validateUpstream(upstream, fieldPath string) error {
	m := upstreamRegex.FindStringSubmatch(upstream)
	if m == nil {
		return &ValidationError{
			Path:    fieldPath,
			Message: "upstream must be an explicit loopback HTTP origin (http://localhost:<port>, http://127.0.0.1:<port>, or http://[::1]:<port>)",
		}
	}
	port, err := strconv.Atoi(m[1])
	if err != nil || port < 1 || port > 65535 {
		return &ValidationError{
			Path:    fieldPath,
			Message: "upstream port must be between 1 and 65535",
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
