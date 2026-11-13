package resolver

import (
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"time"

	alterrors "alt/pkg/errors"
)

const (
	defaultGatewayTimeout = 5 * time.Second
)

// FixtureSource resolves domain records from a content-addressed Manifest fixture in memory or on disk.
type FixtureSource struct {
	expectedCID     string
	expectedNetwork string
	rawManifest     []byte
}

// NewFixtureSource creates a deterministic RecordSource backed by raw manifest bytes.
// If expectedCID is non-empty, VerifyBlockCID is enforced on every resolution.
func NewFixtureSource(rawManifest []byte, expectedCID, expectedNetwork string) *FixtureSource {
	cp := make([]byte, len(rawManifest))
	copy(cp, rawManifest)
	return &FixtureSource{
		expectedCID:     expectedCID,
		expectedNetwork: expectedNetwork,
		rawManifest:     cp,
	}
}

// LoadFixtureSourceFile loads a manifest file from disk as a deterministic RecordSource.
func LoadFixtureSourceFile(path, expectedCID, expectedNetwork string) (*FixtureSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return NewFixtureSource(data, expectedCID, expectedNetwork), nil
}

// Resolve verifies content addressing (if configured), decodes the manifest strictly,
// verifies networkId, and returns the raw ownership and target records for domain.
func (s *FixtureSource) Resolve(_ context.Context, domain string) ([]byte, []byte, error) {
	return extractDomainFromManifest(s.rawManifest, s.expectedCID, s.expectedNetwork, domain)
}

// GatewaySource fetches an explicitly configured raw manifest CID from one or more HTTP IPFS gateways.
// Transport responses are untrusted until CID content-addressing and record signatures pass.
type GatewaySource struct {
	manifestCID     string
	expectedNetwork string
	gateways        []string
	client          *http.Client
	maxBytes        int64
}

// GatewayOptions configures GatewaySource limits and HTTP transport behavior.
type GatewayOptions struct {
	ManifestCID     string
	ExpectedNetwork string
	Gateways        []string
	Timeout         time.Duration
	MaxBytes        int64
	HTTPClient      *http.Client
}

// NewGatewaySource creates an HTTP IPFS gateway RecordSource for an explicit CIDv1 raw block.
func NewGatewaySource(opts GatewayOptions) (*GatewaySource, error) {
	cid := strings.TrimSpace(opts.ManifestCID)
	if cid == "" {
		return nil, fmt.Errorf("resolver: manifestCID is required for GatewaySource")
	}
	if len(opts.Gateways) == 0 {
		return nil, fmt.Errorf("resolver: at least one gateway URL is required for GatewaySource")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultGatewayTimeout
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxManifestBytes
	}

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	cleanedGateways := make([]string, 0, len(opts.Gateways))
	for _, gw := range opts.Gateways {
		trimmed := strings.TrimRight(strings.TrimSpace(gw), "/")
		if trimmed != "" {
			cleanedGateways = append(cleanedGateways, trimmed)
		}
	}
	if len(cleanedGateways) == 0 {
		return nil, fmt.Errorf("resolver: no valid gateway URLs configured")
	}

	return &GatewaySource{
		manifestCID:     cid,
		expectedNetwork: opts.ExpectedNetwork,
		gateways:        cleanedGateways,
		client:          client,
		maxBytes:        maxBytes,
	}, nil
}

// Resolve fetches the configured manifest CID from the gateway list, verifies the SHA-256 CIDv1 digest
// BEFORE JSON decoding, checks content type and byte limits, and extracts the requested domain's records.
func (g *GatewaySource) Resolve(ctx context.Context, domain string) ([]byte, []byte, error) {
	var lastErr error
	for _, gw := range g.gateways {
		raw, err := g.fetchRawBlock(ctx, gw)
		if err != nil {
			lastErr = err
			continue
		}
		// Content-addressing check BEFORE decoding any JSON!
		if err := VerifyBlockCID(g.manifestCID, raw); err != nil {
			lastErr = err
			continue
		}
		return extractDomainFromManifest(raw, g.manifestCID, g.expectedNetwork, domain)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no gateways available")
	}
	return nil, nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "failed to fetch verified manifest from IPFS gateways", lastErr)
}

func (g *GatewaySource) fetchRawBlock(ctx context.Context, gatewayBase string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/ipfs/%s?format=raw", gatewayBase, g.manifestCID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.ipld.raw, application/json, application/octet-stream")

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway %s returned HTTP %d", gatewayBase, resp.StatusCode)
	}

	if err := validateGatewayContentType(resp.Header.Get("Content-Type")); err != nil {
		return nil, err
	}

	if resp.ContentLength > g.maxBytes {
		return nil, fmt.Errorf("gateway response Content-Length %d exceeds limit %d", resp.ContentLength, g.maxBytes)
	}

	limited := io.LimitReader(resp.Body, g.maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > g.maxBytes {
		return nil, fmt.Errorf("gateway response body exceeds %d bytes", g.maxBytes)
	}
	return data, nil
}

func validateGatewayContentType(headerVal string) error {
	if strings.TrimSpace(headerVal) == "" {
		return fmt.Errorf("gateway response missing Content-Type header")
	}
	mediaType, _, err := mime.ParseMediaType(headerVal)
	if err != nil {
		return fmt.Errorf("invalid Content-Type header %q: %w", headerVal, err)
	}
	switch strings.ToLower(mediaType) {
	case "application/vnd.ipld.raw", "application/octet-stream", "application/json":
		return nil
	default:
		return fmt.Errorf("disallowed gateway Content-Type %q", mediaType)
	}
}

func extractDomainFromManifest(raw []byte, expectedCID, expectedNetwork, domain string) ([]byte, []byte, error) {
	if expectedCID != "" {
		if err := VerifyBlockCID(expectedCID, raw); err != nil {
			return nil, nil, err
		}
	}

	manifest, err := DecodeManifestStrict(raw)
	if err != nil {
		return nil, nil, err
	}
	if expectedNetwork != "" && manifest.NetworkID != expectedNetwork {
		return nil, nil, alterrors.New(alterrors.CodeRecordUnavailable,
			fmt.Sprintf("manifest networkId %q does not match expected %q", manifest.NetworkID, expectedNetwork))
	}

	entry, ok := manifest.Records[domain]
	if !ok {
		return nil, nil, alterrors.New(alterrors.CodeNameNotFound, "domain not present in verified manifest: "+domain)
	}
	if len(entry.Ownership) == 0 || len(entry.Target) == 0 {
		return nil, nil, alterrors.New(alterrors.CodeRecordUnavailable, "incomplete manifest entry for "+domain)
	}
	return []byte(entry.Ownership), []byte(entry.Target), nil
}
