package dnsstub_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"alt/pkg/dnsstub"
)

func TestHandleQueryAltAndNonAlt(t *testing.T) {
	cfg := dnsstub.Config{
		IPv4Loopback: net.ParseIP("127.88.0.1"),
		TTL:          60,
	}

	// 1. Valid .alt A query returns 127.88.0.1
	qAlt := dnsstub.EncodeQuery(0x1234, "goker.alt", 1)
	resp, err := dnsstub.HandleQuery(qAlt, cfg)
	if err != nil {
		t.Fatalf("HandleQuery failed: %v", err)
	}
	anCount := binary.BigEndian.Uint16(resp[6:8])
	if anCount != 1 {
		t.Fatalf("expected 1 answer record, got %d", anCount)
	}
	gotIP := resp[len(resp)-4:]
	if !bytes.Equal(gotIP, []byte{127, 88, 0, 1}) {
		t.Fatalf("expected IP 127.88.0.1, got %v", gotIP)
	}

	// 2. AAAA query when IPv6Loopback is not active returns 0 answers (NODATA, NOERROR)
	qAAAA := dnsstub.EncodeQuery(0x1235, "goker.alt", 28)
	respAAAA, err := dnsstub.HandleQuery(qAAAA, cfg)
	if err != nil {
		t.Fatalf("HandleQuery AAAA failed: %v", err)
	}
	if binary.BigEndian.Uint16(respAAAA[6:8]) != 0 {
		t.Fatalf("expected 0 AAAA answers when IPv6 listener is inactive")
	}

	// 3. Non-.alt query returns REFUSED (RCODE = 5)
	qCom := dnsstub.EncodeQuery(0x1236, "example.com", 1)
	respCom, err := dnsstub.HandleQuery(qCom, cfg)
	if err != nil {
		t.Fatalf("HandleQuery example.com failed: %v", err)
	}
	rcode := respCom[3] & 0x0F
	if rcode != 5 {
		t.Fatalf("expected RCODE=5 (REFUSED) for non-.alt domain, got %d", rcode)
	}
}

