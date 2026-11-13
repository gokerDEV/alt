package resolver_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	alterrors "alt/pkg/errors"
	"alt/pkg/profile"
	"alt/pkg/resolver"
)

func buildSignedIPNSRecordV2(
	t *testing.T,
	ipnsPriv ed25519.PrivateKey,
	targetCID string,
	sequence uint64,
	eol time.Time,
	ttl time.Duration,
) []byte {
	t.Helper()
	valBytes := []byte("/ipfs/" + targetCID)
	validityBytes := []byte(eol.UTC().Format(time.RFC3339Nano))

	// Canonical DAG-CBOR map(5) sorted by key byte length then lexicographically:
	// "TTL" (3), "Value" (5), "Sequence" (8), "Validity" (8), "ValidityType" (12)
	var cbor []byte
	cbor = append(cbor, 0xa5) // map(5)

	// "TTL": uint
	cbor = appendCBORText(cbor, "TTL")
	cbor = appendCBORUint(cbor, uint64(ttl))

	// "Value": bytes
	cbor = appendCBORText(cbor, "Value")
	cbor = appendCBORBytes(cbor, valBytes)

	// "Sequence": uint
	cbor = appendCBORText(cbor, "Sequence")
	cbor = appendCBORUint(cbor, sequence)

	// "Validity": bytes
	cbor = appendCBORText(cbor, "Validity")
	cbor = appendCBORBytes(cbor, validityBytes)

	// "ValidityType": uint(0)
	cbor = appendCBORText(cbor, "ValidityType")
	cbor = appendCBORUint(cbor, 0)

	sigInput := append([]byte("ipns-signature:"), cbor...)
	sigV2 := ed25519.Sign(ipnsPriv, sigInput)

	// Protobuf IpnsEntry: field 8 (signatureV2: tag 0x42), field 9 (data: tag 0x4a)
	var proto []byte
	proto = appendProtoBytes(proto, 8, sigV2)
	proto = appendProtoBytes(proto, 9, cbor)
	return proto
}

func appendCBORHead(dst []byte, major byte, n uint64) []byte {
	prefix := major << 5
	switch {
	case n < 24:
		return append(dst, prefix|byte(n))
	case n <= 0xff:
		return append(dst, prefix|24, byte(n))
	case n <= 0xffff:
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(n))
		return append(append(dst, prefix|25), b[:]...)
	case n <= 0xffffffff:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(n))
		return append(append(dst, prefix|26), b[:]...)
	default:
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], n)
		return append(append(dst, prefix|27), b[:]...)
	}
}

func appendCBORUint(dst []byte, n uint64) []byte {
	return appendCBORHead(dst, 0, n)
}

func appendCBORBytes(dst []byte, b []byte) []byte {
	dst = appendCBORHead(dst, 2, uint64(len(b)))
	return append(dst, b...)
}

func appendCBORText(dst []byte, s string) []byte {
	dst = appendCBORHead(dst, 3, uint64(len(s)))
	return append(dst, []byte(s)...)
}

func appendProtoBytes(dst []byte, fieldNum uint64, b []byte) []byte {
	var tagBuf [binary.MaxVarintLen64]byte
	tn := binary.PutUvarint(tagBuf[:], (fieldNum<<3)|2)
	dst = append(dst, tagBuf[:tn]...)
	ln := binary.PutUvarint(tagBuf[:], uint64(len(b)))
	dst = append(dst, tagBuf[:ln]...)
	return append(dst, b...)
}

func TestIPNSSourceVerifiesSignatureSequenceAndFallback(t *testing.T) {
	ipnsPub, ipnsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k51Root, err := resolver.EncodeK51Ed25519PublicKey(ipnsPub)
	if err != nil {
		t.Fatal(err)
	}
	decodedPub, err := resolver.ParseK51Ed25519PublicKey(k51Root)
	if err != nil || string(decodedPub) != string(ipnsPub) {
		t.Fatalf("k51 roundtrip failed: %v", err)
	}

	b1 := buildTestBundle(t, "alt-main-v1", "alt", "goker.alt", 1, 1, "2030-01-01T00:00:00Z", "2028-01-01T00:00:00Z")
	b2 := signBundleWithKeys(t, b1.authPub, b1.authPriv, b1.ownerPub, b1.ownerPriv,
		"alt-main-v1", "alt", "goker.alt", 1, 2, "2030-01-01T00:00:00Z", "2028-01-01T00:00:00Z")
	bootstrapBundle := signBundleWithKeys(t, b1.authPub, b1.authPriv, b1.ownerPub, b1.ownerPriv,
		"alt-main-v1", "alt", "register.alt", 1, 1, "2030-01-01T00:00:00Z", "2028-01-01T00:00:00Z")

	var mu sync.Mutex
	now := b1.now
	getNow := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advanceNow := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	currentIPNSBytes := buildSignedIPNSRecordV2(t, ipnsPriv, b1.manifestCID, 10, getNow().Add(24*time.Hour), time.Millisecond)
	blocks := map[string][]byte{
		b1.manifestCID:              b1.manifestJSON,
		b2.manifestCID:              b2.manifestJSON,
		bootstrapBundle.manifestCID: bootstrapBundle.manifestJSON,
	}
	var failIPNS bool

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fail := failIPNS
		ipnsCopy := append([]byte(nil), currentIPNSBytes...)
		mu.Unlock()

		switch r.URL.Path {
		case "/ipns/" + k51Root:
			if fail {
				http.Error(w, "ipns unavailable", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.ipfs.ipns-record")
			_, _ = w.Write(ipnsCopy)
		case "/ipfs/" + b1.manifestCID, "/ipfs/" + b2.manifestCID, "/ipfs/" + bootstrapBundle.manifestCID:
			cid := r.URL.Path[len("/ipfs/"):]
			w.Header().Set("Content-Type", "application/vnd.ipld.raw")
			_, _ = w.Write(blocks[cid])
		default:
			http.NotFound(w, r)
		}
	}))
	defer gw.Close()

	src, err := resolver.NewIPNSSource(resolver.IPNSOptions{
		IPNSRoot:        k51Root,
		BootstrapCID:    bootstrapBundle.manifestCID,
		ExpectedNetwork: "alt-main-v1",
		Gateways:        []string{gw.URL},
		CacheTTL:        time.Nanosecond,
		Clock:           getNow,
	})
	if err != nil {
		t.Fatal(err)
	}

	res := resolver.NewWithConfig(resolver.Config{
		Profile: b1.prof,
		Source:  src,
		Clock:   getNow,
	})

	// 1. Resolve user domain via verified IPNS V2 signature + raw block CIDv1 check
	out1, err := res.Resolve(context.Background(), "goker.alt")
	if err != nil {
		t.Fatalf("Resolve goker.alt via IPNS failed: %v", err)
	}
	if out1.Target.Sequence != 1 {
		t.Fatalf("expected sequence 1, got %d", out1.Target.Sequence)
	}

	// 2. Advance clock past CacheTTL and advance IPNS sequence 10 -> 11 pointing to b2 (target sequence 2)
	advanceNow(time.Second)
	mu.Lock()
	currentIPNSBytes = buildSignedIPNSRecordV2(t, ipnsPriv, b2.manifestCID, 11, getNowSafe(now).Add(24*time.Hour), time.Millisecond)
	mu.Unlock()
	out2, err := res.Resolve(context.Background(), "goker.alt")
	if err != nil || out2.Target.Sequence != 2 {
		t.Fatalf("expected updated target sequence 2, got %v (err=%v)", out2, err)
	}

	// 3. Attempt IPNS sequence rollback (11 -> 9) signed by the real IPNS key -> rejected!
	srcUncached, _ := resolver.NewIPNSSource(resolver.IPNSOptions{
		IPNSRoot:        k51Root,
		ExpectedNetwork: "alt-main-v1",
		Gateways:        []string{gw.URL},
		CacheTTL:        time.Nanosecond,
		Clock:           getNow,
	})
	// Prime srcUncached with seq 11 first
	if _, _, err := srcUncached.Resolve(context.Background(), "goker.alt"); err != nil {
		t.Fatalf("prime seq 11 failed: %v", err)
	}
	advanceNow(2 * time.Second)
	mu.Lock()
	currentIPNSBytes = buildSignedIPNSRecordV2(t, ipnsPriv, b1.manifestCID, 9, getNowSafe(now).Add(24*time.Hour), time.Millisecond)
	mu.Unlock()
	if _, _, err := srcUncached.Resolve(context.Background(), "goker.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected IPNS sequence rollback to be rejected with RECORD_UNAVAILABLE, got: %v", err)
	}

	// 4. Forged IPNS signature from attacker key is rejected
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	mu.Lock()
	currentIPNSBytes = buildSignedIPNSRecordV2(t, roguePriv, b2.manifestCID, 99, getNowSafe(now).Add(24*time.Hour), time.Millisecond)
	mu.Unlock()
	if _, _, err := srcUncached.Resolve(context.Background(), "goker.alt"); !alterrors.IsCode(err, alterrors.CodeRecordUnavailable) {
		t.Fatalf("expected forged IPNS signature to fail with RECORD_UNAVAILABLE, got: %v", err)
	}

	// 5. Bootstrap fallback resolves register.alt when IPNS endpoint is unreachable
	mu.Lock()
	failIPNS = true
	mu.Unlock()
	advanceNow(2 * time.Second)
	regRes, err := res.Resolve(context.Background(), "register.alt")
	if err != nil || regRes.Ownership.Domain != "register.alt" {
		t.Fatalf("expected bootstrap fallback for register.alt when IPNS is down, got %v (err=%v)", regRes, err)
	}
}

func getNowSafe(t time.Time) time.Time { return t }

func TestLiveOfficialIPNSProfileResolution(t *testing.T) {
	if os.Getenv("ALT_LIVE_IPNS_TEST") != "1" {
		t.Skip("set ALT_LIVE_IPNS_TEST=1 to run live Filebase IPNS resolution check")
	}

	prof := profile.Official()
	src, err := resolver.NewIPNSSource(resolver.IPNSOptions{
		IPNSRoot:        prof.Resolver.IPNSRoot,
		BootstrapCID:    prof.Resolver.ManifestCID,
		ExpectedNetwork: prof.NetworkID,
		Gateways:        prof.Resolver.Gateways,
	})
	if err != nil {
		t.Fatalf("NewIPNSSource: %v", err)
	}

	res, err := resolver.NewChecked(resolver.Config{
		Profile: prof,
		Source:  src,
	})
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	reg, err := res.Resolve(ctx, "register.alt")
	if err != nil {
		t.Fatalf("live Resolve(register.alt) failed: %v", err)
	}
	if reg.Target.Target != "https://alt.goker.dev" {
		t.Fatalf("unexpected register.alt target: %q", reg.Target.Target)
	}

	if extraDomain := os.Getenv("ALT_LIVE_IPNS_EXPECT_DOMAIN"); extraDomain != "" {
		manifestCID := os.Getenv("ALT_LIVE_MANIFEST_CID")
		var domainRes *resolver.VerifiedResolution
		if manifestCID != "" {
			// Verify newly pinned CARv1 raw block immediately via Trustless Gateway without waiting out 300s CDN IPNS edge TTL
			gwSrc, gwErr := resolver.NewGatewaySource(resolver.GatewayOptions{
				ManifestCID:     manifestCID,
				ExpectedNetwork: prof.NetworkID,
				Gateways:        prof.Resolver.Gateways,
			})
			if gwErr != nil {
				t.Fatalf("NewGatewaySource(%s): %v", manifestCID, gwErr)
			}
			gwResolver, gwErr := resolver.NewChecked(resolver.Config{
				Profile: prof,
				Source:  gwSrc,
			})
			if gwErr != nil {
				t.Fatalf("NewChecked(GatewaySource): %v", gwErr)
			}
			// Must contain both immutable register.alt and the newly published user domain!
			if _, err := gwResolver.Resolve(ctx, "register.alt"); err != nil {
				t.Fatalf("live GatewaySource(%s) Resolve(register.alt) failed: %v", manifestCID, err)
			}
			domainRes, err = gwResolver.Resolve(ctx, extraDomain)
		} else {
			domainRes, err = res.Resolve(ctx, extraDomain)
		}
		if err != nil {
			t.Fatalf("live Resolve(%s) failed: %v", extraDomain, err)
		}
		if expectedTarget := os.Getenv("ALT_LIVE_IPNS_EXPECT_TARGET"); expectedTarget != "" && domainRes.Target.Target != expectedTarget {
			t.Fatalf("unexpected %s target: got %q, want %q", extraDomain, domainRes.Target.Target, expectedTarget)
		}
	}
}
