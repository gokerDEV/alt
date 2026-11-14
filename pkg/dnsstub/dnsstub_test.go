package dnsstub_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

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

	// 4. RFC 9462 DDR `_dns.resolver.arpa` SVCB (64) returns NOERROR/NODATA so mDNSResponder stops probing cleanly
	qDDR := dnsstub.EncodeQuery(0x1237, "_dns.resolver.arpa", 64)
	respDDR, err := dnsstub.HandleQuery(qDDR, cfg)
	if err != nil {
		t.Fatalf("HandleQuery _dns.resolver.arpa failed: %v", err)
	}
	if gotRcode := respDDR[3] & 0x0F; gotRcode != 0 {
		t.Fatalf("expected RCODE=0 (NOERROR) for _dns.resolver.arpa, got %d", gotRcode)
	}
	if binary.BigEndian.Uint16(respDDR[6:8]) != 0 {
		t.Fatalf("expected 0 answers for _dns.resolver.arpa")
	}
}

func TestServeTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen tcp: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = dnsstub.ServeTCP(ctx, ln, dnsstub.Config{
			IPv4Loopback: net.ParseIP("127.0.0.2"),
			TTL:          60,
			TLD:          "alt",
		})
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("Dial tcp: %v", err)
	}
	defer conn.Close()

	q := dnsstub.EncodeQuery(0x4242, "goker.alt", 1)
	frame := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(q)))
	copy(frame[2:], q)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("Write tcp query: %v", err)
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("ReadFull length: %v", err)
	}
	resp := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("ReadFull body: %v", err)
	}
	if got := resp[len(resp)-4:]; !bytes.Equal(got, []byte{127, 0, 0, 2}) {
		t.Fatalf("expected 127.0.0.2 over TCP DNS, got %v", got)
	}
}
