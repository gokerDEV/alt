package resolver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	alterrors "alt/pkg/errors"
)

const (
	ipnsSignatureV2Prefix = "ipns-signature:"
	maxIPNSRecordBytes    = 64 * 1024 // 64 KiB upper bound for a signed IPNS protobuf record
)

// VerifiedIPNSRecord holds the verified fields extracted from an Ed25519-signed IPNS V2 record.
type VerifiedIPNSRecord struct {
	TargetCID string
	Sequence  uint64
	ExpiresAt time.Time
	TTL       time.Duration
}

// ParseK51Ed25519PublicKey decodes a self-certifying base36 `k51...` CIDv1 libp2p-key
// (`0x01` version, `0x72` libp2p-key multicodec, `0x00` identity multihash, `0x24` 36-byte
// protobuf `PublicKey{Type: Ed25519(1), Data: 32-byte key}`) into a 32-byte Ed25519 public key.
func ParseK51Ed25519PublicKey(ipnsRoot string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(ipnsRoot)
	if !strings.HasPrefix(trimmed, "k") || len(trimmed) < 50 {
		return nil, fmt.Errorf("ipns: invalid base36 libp2p-key identifier %q", ipnsRoot)
	}

	z := new(big.Int)
	if _, ok := z.SetString(strings.ToLower(trimmed[1:]), 36); !ok {
		return nil, fmt.Errorf("ipns: malformed base36 encoding in ipnsRoot")
	}

	raw := z.Bytes()
	// Base36 big.Int strips leading 0x00 bytes if any, though CIDv1 starts with 0x01 so length is 40 bytes.
	if len(raw) != 40 {
		return nil, fmt.Errorf("ipns: unexpected decoded libp2p-key CID length %d (expected 40 bytes for Ed25519)", len(raw))
	}

	// Expected header: 0x01 (CIDv1), 0x72 (libp2p-key), 0x00 (identity mh), 0x24 (36 bytes),
	// 0x08 0x01 (protobuf field 1 varint = KeyType Ed25519), 0x12 0x20 (protobuf field 2 len 32)
	expectedHeader := []byte{0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20}
	if !bytes.Equal(raw[:len(expectedHeader)], expectedHeader) {
		return nil, fmt.Errorf("ipns: unsupported ipnsRoot multicodec or key type (expected CIDv1 libp2p-key Ed25519)")
	}

	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, raw[len(expectedHeader):])
	return pub, nil
}

// EncodeK51Ed25519PublicKey encodes a 32-byte Ed25519 public key into its canonical base36 `k51...` IPNS root string.
func EncodeK51Ed25519PublicKey(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("ipns: invalid ed25519 public key length %d", len(pub))
	}
	buf := make([]byte, 0, 40)
	buf = append(buf, 0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20)
	buf = append(buf, pub...)
	z := new(big.Int).SetBytes(buf)
	return "k" + strings.ToLower(z.Text(36)), nil
}

// VerifyIPNSRecordV2 parses an untrusted `application/vnd.ipfs.ipns-record` protobuf (`IpnsEntry`),
// verifies its Ed25519 V2 signature (`"ipns-signature:" || data`) against the self-certifying `k51...` key,
// checks EOL validity against `now`, and extracts the target raw CIDv1.
func VerifyIPNSRecordV2(rawRecord []byte, expectedIPNSRoot string, now time.Time) (*VerifiedIPNSRecord, error) {
	if len(rawRecord) == 0 || len(rawRecord) > maxIPNSRecordBytes {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "invalid IPNS record byte length")
	}

	pubKey, err := ParseK51Ed25519PublicKey(expectedIPNSRoot)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeInvalidConfig, "invalid ipnsRoot public key", err)
	}

	pubKeyField, sigV2, cborData, err := parseIPNSEntryProtobuf(rawRecord)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "malformed IPNS protobuf record", err)
	}
	if len(sigV2) != ed25519.SignatureSize || len(cborData) == 0 {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "IPNS record missing V2 Ed25519 signature or DAG-CBOR data")
	}

	// If optional pubKey protobuf field (field 7) is present, ensure it matches the inline k51 key.
	if len(pubKeyField) > 0 {
		expectedPubProto := append([]byte{0x08, 0x01, 0x12, 0x20}, pubKey...)
		if !bytes.Equal(pubKeyField, expectedPubProto) {
			return nil, alterrors.New(alterrors.CodeRecordUnavailable, "IPNS embedded pubKey disagrees with self-certifying ipnsRoot")
		}
	}

	signingInput := make([]byte, 0, len(ipnsSignatureV2Prefix)+len(cborData))
	signingInput = append(signingInput, []byte(ipnsSignatureV2Prefix)...)
	signingInput = append(signingInput, cborData...)

	if !ed25519.Verify(pubKey, signingInput, sigV2) {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "IPNS V2 Ed25519 signature verification failed")
	}

	parsedCBOR, err := parseIPNSDagCBORData(cborData)
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "malformed IPNS DAG-CBOR payload", err)
	}

	if parsedCBOR.validityType != 0 {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, fmt.Sprintf("unsupported IPNS ValidityType %d (expected EOL=0)", parsedCBOR.validityType))
	}

	eolTime, err := time.Parse(time.RFC3339Nano, string(parsedCBOR.validity))
	if err != nil {
		return nil, alterrors.Wrap(alterrors.CodeRecordUnavailable, "invalid IPNS EOL timestamp", err)
	}
	if !now.Before(eolTime) {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, "IPNS record has expired")
	}

	valStr := strings.TrimSpace(string(parsedCBOR.value))
	if !strings.HasPrefix(valStr, "/ipfs/") {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, fmt.Sprintf("IPNS Value %q must point to /ipfs/<cid>", valStr))
	}
	targetCID := strings.TrimSpace(strings.TrimPrefix(valStr, "/ipfs/"))
	if strings.Contains(targetCID, "/") || !strings.HasPrefix(targetCID, "b") {
		return nil, alterrors.New(alterrors.CodeRecordUnavailable, fmt.Sprintf("IPNS target CID %q is not a base32 CIDv1 raw block", targetCID))
	}

	ttlDur := 60 * time.Second
	if parsedCBOR.hasTTL && parsedCBOR.ttlNs > 0 {
		if parsedCBOR.ttlNs > uint64(24*time.Hour) {
			ttlDur = 24 * time.Hour
		} else {
			ttlDur = time.Duration(parsedCBOR.ttlNs)
		}
	}

	return &VerifiedIPNSRecord{
		TargetCID: targetCID,
		Sequence:  parsedCBOR.sequence,
		ExpiresAt: eolTime,
		TTL:       ttlDur,
	}, nil
}

func parseIPNSEntryProtobuf(buf []byte) (pubKey, sigV2, data []byte, err error) {
	i := 0
	for i < len(buf) {
		tag, n := binary.Uvarint(buf[i:])
		if n <= 0 {
			return nil, nil, nil, errors.New("invalid protobuf tag varint")
		}
		i += n
		fieldNum := tag >> 3
		wireType := tag & 0x07

		switch wireType {
		case 0: // varint
			_, vn := binary.Uvarint(buf[i:])
			if vn <= 0 {
				return nil, nil, nil, errors.New("invalid protobuf varint field")
			}
			i += vn
		case 1: // 64-bit
			if i+8 > len(buf) {
				return nil, nil, nil, errors.New("truncated 64-bit protobuf field")
			}
			i += 8
		case 2: // length-delimited bytes
			length, ln := binary.Uvarint(buf[i:])
			if ln <= 0 || length > uint64(len(buf)-i-ln) {
				return nil, nil, nil, errors.New("invalid length-delimited protobuf field")
			}
			i += ln
			val := buf[i : i+int(length)]
			i += int(length)
			switch fieldNum {
			case 7:
				pubKey = val
			case 8:
				sigV2 = val
			case 9:
				data = val
			}
		case 5: // 32-bit
			if i+4 > len(buf) {
				return nil, nil, nil, errors.New("truncated 32-bit protobuf field")
			}
			i += 4
		default:
			return nil, nil, nil, fmt.Errorf("unsupported protobuf wire type %d", wireType)
		}
	}
	return pubKey, sigV2, data, nil
}

type ipnsCBORFields struct {
	value        []byte
	validity     []byte
	validityType uint64
	sequence     uint64
	ttlNs        uint64
	hasValue     bool
	hasValidity  bool
	hasValType   bool
	hasSequence  bool
	hasTTL       bool
}

func parseIPNSDagCBORData(buf []byte) (*ipnsCBORFields, error) {
	if len(buf) == 0 {
		return nil, errors.New("empty CBOR buffer")
	}
	major := buf[0] >> 5
	if major != 5 { // CBOR map
		return nil, errors.New("expected top-level CBOR map in IpnsEntry.data")
	}
	mapLen, offset, err := readCBORHead(buf, 0)
	if err != nil {
		return nil, err
	}
	if mapLen > 32 {
		return nil, errors.New("excessive keys in IPNS CBOR map")
	}

	out := &ipnsCBORFields{}
	for idx := uint64(0); idx < mapLen; idx++ {
		if offset >= len(buf) || (buf[offset]>>5) != 3 { // text string key
			return nil, errors.New("expected CBOR text string map key")
		}
		keyLen, nextOff, err := readCBORHead(buf, offset)
		if err != nil || keyLen > uint64(len(buf)-nextOff) {
			return nil, errors.New("invalid CBOR map key length")
		}
		key := string(buf[nextOff : nextOff+int(keyLen)])
		offset = nextOff + int(keyLen)

		if offset >= len(buf) {
			return nil, errors.New("unexpected EOF after CBOR map key")
		}
		valMajor := buf[offset] >> 5

		switch key {
		case "Value":
			if valMajor != 2 { // byte string
				return nil, errors.New("IPNS CBOR Value must be byte string")
			}
			bLen, vOff, err := readCBORHead(buf, offset)
			if err != nil || bLen > uint64(len(buf)-vOff) {
				return nil, errors.New("invalid IPNS CBOR Value bytes")
			}
			out.value = buf[vOff : vOff+int(bLen)]
			out.hasValue = true
			offset = vOff + int(bLen)
		case "Validity":
			if valMajor != 2 { // byte string
				return nil, errors.New("IPNS CBOR Validity must be byte string")
			}
			bLen, vOff, err := readCBORHead(buf, offset)
			if err != nil || bLen > uint64(len(buf)-vOff) {
				return nil, errors.New("invalid IPNS CBOR Validity bytes")
			}
			out.validity = buf[vOff : vOff+int(bLen)]
			out.hasValidity = true
			offset = vOff + int(bLen)
		case "ValidityType":
			if valMajor != 0 { // unsigned int
				return nil, errors.New("IPNS CBOR ValidityType must be uint")
			}
			uVal, vOff, err := readCBORHead(buf, offset)
			if err != nil {
				return nil, err
			}
			out.validityType = uVal
			out.hasValType = true
			offset = vOff
		case "Sequence":
			if valMajor != 0 { // unsigned int
				return nil, errors.New("IPNS CBOR Sequence must be uint")
			}
			uVal, vOff, err := readCBORHead(buf, offset)
			if err != nil {
				return nil, err
			}
			out.sequence = uVal
			out.hasSequence = true
			offset = vOff
		case "TTL":
			if valMajor != 0 { // unsigned int
				return nil, errors.New("IPNS CBOR TTL must be uint")
			}
			uVal, vOff, err := readCBORHead(buf, offset)
			if err != nil {
				return nil, err
			}
			out.ttlNs = uVal
			out.hasTTL = true
			offset = vOff
		default:
			next, err := skipCBORItem(buf, offset, 0)
			if err != nil {
				return nil, err
			}
			offset = next
		}
	}

	if offset != len(buf) {
		return nil, errors.New("trailing bytes after IPNS DAG-CBOR map")
	}
	if !out.hasValue || !out.hasValidity || !out.hasValType || !out.hasSequence {
		return nil, errors.New("IPNS DAG-CBOR payload missing mandatory Value, Validity, ValidityType, or Sequence")
	}
	return out, nil
}

func readCBORHead(buf []byte, pos int) (uint64, int, error) {
	if pos >= len(buf) {
		return 0, pos, io.ErrUnexpectedEOF
	}
	addl := buf[pos] & 0x1f
	pos++
	switch {
	case addl < 24:
		return uint64(addl), pos, nil
	case addl == 24:
		if pos+1 > len(buf) {
			return 0, pos, io.ErrUnexpectedEOF
		}
		return uint64(buf[pos]), pos + 1, nil
	case addl == 25:
		if pos+2 > len(buf) {
			return 0, pos, io.ErrUnexpectedEOF
		}
		return uint64(binary.BigEndian.Uint16(buf[pos : pos+2])), pos + 2, nil
	case addl == 26:
		if pos+4 > len(buf) {
			return 0, pos, io.ErrUnexpectedEOF
		}
		return uint64(binary.BigEndian.Uint32(buf[pos : pos+4])), pos + 4, nil
	case addl == 27:
		if pos+8 > len(buf) {
			return 0, pos, io.ErrUnexpectedEOF
		}
		return binary.BigEndian.Uint64(buf[pos : pos+8]), pos + 8, nil
	default:
		return 0, pos, errors.New("indefinite or reserved CBOR additional info not allowed in DAG-CBOR")
	}
}

func skipCBORItem(buf []byte, pos int, depth int) (int, error) {
	if depth > 8 || pos >= len(buf) {
		return pos, errors.New("CBOR nesting limit or EOF exceeded")
	}
	major := buf[pos] >> 5
	val, next, err := readCBORHead(buf, pos)
	if err != nil {
		return pos, err
	}
	switch major {
	case 0, 1, 7: // uint, negint, simple/float
		return next, nil
	case 2, 3: // bytes, text
		if val > uint64(len(buf)-next) {
			return pos, io.ErrUnexpectedEOF
		}
		return next + int(val), nil
	case 4: // array
		cur := next
		for i := uint64(0); i < val; i++ {
			cur, err = skipCBORItem(buf, cur, depth+1)
			if err != nil {
				return pos, err
			}
		}
		return cur, nil
	case 5: // map
		cur := next
		for i := uint64(0); i < val*2; i++ {
			cur, err = skipCBORItem(buf, cur, depth+1)
			if err != nil {
				return pos, err
			}
		}
		return cur, nil
	case 6: // tag
		return skipCBORItem(buf, next, depth+1)
	default:
		return pos, errors.New("unknown CBOR major type")
	}
}

// IPNSOptions configures IPNSSource for trustless IPNS + raw CIDv1 manifest resolution.
type IPNSOptions struct {
	IPNSRoot            string
	BootstrapCID        string // Optional fixed bootstrap CID fallback (e.g., for register.alt)
	ExpectedNetwork     string
	Gateways            []string
	Timeout             time.Duration
	MaxBytes            int64
	CacheTTL            time.Duration
	Clock               func() time.Time
	HTTPClient          *http.Client
}

// IPNSSource resolves an authenticated IPNS root (`k51...`) via Trustless IPFS HTTP Gateways:
//  1. Fetches `/ipns/<ipnsRoot>?format=ipns-record` (`application/vnd.ipfs.ipns-record`),
//  2. Verifies the Ed25519 V2 signature against the self-certifying `k51...` public key,
//  3. Enforces monotonic IPNS `Sequence` anti-rollback and EOL expiration,
//  4. Fetches `/ipfs/<resolvedCid>?format=raw` and verifies `VerifyBlockCID` BEFORE JSON decoding,
//  5. Optionally falls back to a pinned `BootstrapCID` when IPNS is unreachable or does not contain a bootstrap record.
type IPNSSource struct {
	ipnsRoot        string
	bootstrapSource *GatewaySource
	expectedNetwork string
	gateways        []string
	client          *http.Client
	maxBytes        int64
	cacheTTL        time.Duration
	nowFn           func() time.Time

	mu             sync.Mutex
	highestSeq     uint64
	hasSeenSeq     bool
	cachedCID      string
	cachedManifest []byte
	cacheExpiresAt time.Time
}

// NewIPNSSource creates a verifiable IPNS RecordSource backed by one or more Trustless IPFS Gateways.
func NewIPNSSource(opts IPNSOptions) (*IPNSSource, error) {
	root := strings.TrimSpace(opts.IPNSRoot)
	if _, err := ParseK51Ed25519PublicKey(root); err != nil {
		return nil, fmt.Errorf("resolver: invalid ipnsRoot for IPNSSource: %w", err)
	}
	if len(opts.Gateways) == 0 {
		return nil, fmt.Errorf("resolver: at least one gateway URL is required for IPNSSource")
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultGatewayTimeout
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = MaxManifestBytes
	}
	cacheTTL := opts.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = 15 * time.Second
	}
	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
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

	var bootstrapSrc *GatewaySource
	if strings.TrimSpace(opts.BootstrapCID) != "" {
		var err error
		bootstrapSrc, err = NewGatewaySource(GatewayOptions{
			ManifestCID:     opts.BootstrapCID,
			ExpectedNetwork: opts.ExpectedNetwork,
			Gateways:        cleanedGateways,
			Timeout:         timeout,
			MaxBytes:        maxBytes,
			HTTPClient:      client,
		})
		if err != nil {
			return nil, err
		}
	}

	return &IPNSSource{
		ipnsRoot:        root,
		bootstrapSource: bootstrapSrc,
		expectedNetwork: opts.ExpectedNetwork,
		gateways:        cleanedGateways,
		client:          client,
		maxBytes:        maxBytes,
		cacheTTL:        cacheTTL,
		nowFn:           clock,
	}, nil
}

// Resolve resolves `domain` from the latest Ed25519-verified IPNS manifest snapshot,
// falling back to the fixed bootstrap manifest CID if IPNS transport is unavailable.
func (s *IPNSSource) Resolve(ctx context.Context, domain string) ([]byte, []byte, error) {
	rawManifest, cid, err := s.fetchVerifiedManifest(ctx)
	if err == nil {
		own, tgt, extractErr := extractDomainFromManifest(rawManifest, cid, s.expectedNetwork, domain)
		if extractErr == nil || !alterrors.IsCode(extractErr, alterrors.CodeNameNotFound) || s.bootstrapSource == nil {
			return own, tgt, extractErr
		}
		// If domain is not in IPNS manifest (unlikely since register.alt is always included) and bootstrap exists, check bootstrap.
		return s.bootstrapSource.Resolve(ctx, domain)
	}

	if s.bootstrapSource != nil {
		if own, tgt, fbErr := s.bootstrapSource.Resolve(ctx, domain); fbErr == nil {
			return own, tgt, nil
		}
	}
	return nil, nil, err
}

func (s *IPNSSource) fetchVerifiedManifest(ctx context.Context) ([]byte, string, error) {
	now := s.nowFn()

	s.mu.Lock()
	if len(s.cachedManifest) > 0 && now.Before(s.cacheExpiresAt) {
		cp := append([]byte(nil), s.cachedManifest...)
		cid := s.cachedCID
		s.mu.Unlock()
		return cp, cid, nil
	}
	minSeq := s.highestSeq
	hasSeen := s.hasSeenSeq
	prevCID := s.cachedCID
	prevManifest := append([]byte(nil), s.cachedManifest...)
	s.mu.Unlock()

	var bestRec *VerifiedIPNSRecord
	var bestGateway string
	var lastErr error

	// Query gateways for signed IPNS record; pick the highest valid sequence across reachable gateways.
	for _, gw := range s.gateways {
		recBytes, err := s.fetchIPNSRecordBytes(ctx, gw)
		if err != nil {
			lastErr = err
			continue
		}
		verified, err := VerifyIPNSRecordV2(recBytes, s.ipnsRoot, now)
		if err != nil {
			lastErr = err
			continue
		}
		if hasSeen && verified.Sequence < minSeq {
			lastErr = alterrors.New(alterrors.CodeRecordUnavailable,
				fmt.Sprintf("IPNS sequence rollback rejected: got %d, want >= %d", verified.Sequence, minSeq))
			continue
		}
		if bestRec == nil || verified.Sequence > bestRec.Sequence {
			bestRec = verified
			bestGateway = gw
		}
	}

	if bestRec == nil {
		if lastErr == nil {
			lastErr = errors.New("no gateways returned a valid IPNS record")
		}
		return nil, "", alterrors.Wrap(alterrors.CodeRecordUnavailable, "failed to resolve verified IPNS pointer", lastErr)
	}

	// Fast path: if the verified IPNS sequence points to the exact CID we already verified in memory, reuse bytes!
	if bestRec.TargetCID == prevCID && len(prevManifest) > 0 {
		if err := VerifyBlockCID(bestRec.TargetCID, prevManifest); err == nil {
			s.commitManifestCache(bestRec, prevManifest, now)
			return prevManifest, bestRec.TargetCID, nil
		}
	}

	// Fetch the raw block for `bestRec.TargetCID`, preferring the gateway that served the fresh IPNS record first.
	orderedGateways := make([]string, 0, len(s.gateways))
	if bestGateway != "" {
		orderedGateways = append(orderedGateways, bestGateway)
	}
	for _, gw := range s.gateways {
		if gw != bestGateway {
			orderedGateways = append(orderedGateways, gw)
		}
	}

	var blockErr error
	for _, gw := range orderedGateways {
		rawBlock, err := fetchGatewayRawBlock(ctx, s.client, gw, bestRec.TargetCID, s.maxBytes)
		if err != nil {
			blockErr = err
			continue
		}
		if err := VerifyBlockCID(bestRec.TargetCID, rawBlock); err != nil {
			blockErr = err
			continue
		}
		// Ensure manifest decodes and matches expected network before caching
		m, err := DecodeManifestStrict(rawBlock)
		if err != nil {
			blockErr = err
			continue
		}
		if s.expectedNetwork != "" && m.NetworkID != s.expectedNetwork {
			blockErr = alterrors.New(alterrors.CodeRecordUnavailable,
				fmt.Sprintf("IPNS manifest networkId %q does not match expected %q", m.NetworkID, s.expectedNetwork))
			continue
		}

		s.commitManifestCache(bestRec, rawBlock, now)
		return rawBlock, bestRec.TargetCID, nil
	}

	if blockErr == nil {
		blockErr = errors.New("unable to fetch verified manifest block for IPNS target")
	}
	return nil, "", alterrors.Wrap(alterrors.CodeRecordUnavailable, "failed to fetch raw manifest block referenced by IPNS", blockErr)
}

func (s *IPNSSource) commitManifestCache(rec *VerifiedIPNSRecord, raw []byte, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasSeenSeq && rec.Sequence < s.highestSeq {
		return
	}
	ttl := s.cacheTTL
	if rec.TTL > 0 && rec.TTL < ttl {
		ttl = rec.TTL
	}
	exp := now.Add(ttl)
	if rec.ExpiresAt.Before(exp) {
		exp = rec.ExpiresAt
	}
	s.hasSeenSeq = true
	s.highestSeq = rec.Sequence
	s.cachedCID = rec.TargetCID
	s.cachedManifest = append([]byte(nil), raw...)
	s.cacheExpiresAt = exp
}

func (s *IPNSSource) fetchIPNSRecordBytes(ctx context.Context, gatewayBase string) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/ipns/%s?format=ipns-record", gatewayBase, s.ipnsRoot)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.ipfs.ipns-record")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway %s IPNS returned HTTP %d", gatewayBase, resp.StatusCode)
	}

	ct := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if ct == "" {
		return nil, fmt.Errorf("gateway %s IPNS response missing Content-Type", gatewayBase)
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return nil, fmt.Errorf("invalid IPNS Content-Type %q: %w", ct, err)
	}
	switch strings.ToLower(mediaType) {
	case "application/vnd.ipfs.ipns-record", "application/octet-stream":
	default:
		return nil, fmt.Errorf("disallowed IPNS Content-Type %q", mediaType)
	}

	limited := io.LimitReader(resp.Body, maxIPNSRecordBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxIPNSRecordBytes {
		return nil, fmt.Errorf("IPNS record exceeds %d bytes", maxIPNSRecordBytes)
	}
	return data, nil
}

func fetchGatewayRawBlock(ctx context.Context, client *http.Client, gatewayBase, cid string, maxBytes int64) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/ipfs/%s?format=raw", gatewayBase, cid)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.ipld.raw, application/json, application/octet-stream")

	resp, err := client.Do(req)
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

	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("gateway response Content-Length %d exceeds limit %d", resp.ContentLength, maxBytes)
	}

	limited := io.LimitReader(resp.Body, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("gateway response body exceeds %d bytes", maxBytes)
	}
	return data, nil
}

