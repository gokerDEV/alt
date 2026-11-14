package dnsstub

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"alt/pkg/names"
)

const (
	qTypeA    uint16 = 1
	qTypeAAAA uint16 = 28
	qClassIN  uint16 = 1

	rCodeNoError uint8 = 0
	rCodeFormErr uint8 = 1
	rCodeRefused uint8 = 5
)

var (
	ErrMalformedPacket = errors.New("dnsstub: malformed DNS packet")
)

// Config holds the active loopback addresses that the local DNS stub announces for .alt queries (§4.1).
type Config struct {
	IPv4Loopback net.IP // e.g., net.ParseIP("127.88.0.1")
	IPv6Loopback net.IP // Optional active IPv6 loopback
	TTL          uint32
	TLD          string // Defaults to names.DefaultTLD.
}

// HandleQuery processes a raw DNS UDP query packet and returns the wire-format DNS response.
// Queries outside the .alt TLD receive REFUSED. Only active loopback addresses are returned.
func HandleQuery(req []byte, cfg Config) ([]byte, error) {
	if len(req) < 12 {
		return nil, ErrMalformedPacket
	}

	txID := binary.BigEndian.Uint16(req[0:2])
	flags := binary.BigEndian.Uint16(req[2:4])
	qdCount := binary.BigEndian.Uint16(req[4:6])

	// Reject responses (QR == 1) or empty question sections
	if (flags&0x8000) != 0 || qdCount == 0 {
		return buildErrorResponse(txID, flags, nil, rCodeFormErr), nil
	}

	qName, offset, err := decodeQName(req, 12)
	if err != nil || offset+4 > len(req) {
		return buildErrorResponse(txID, flags, nil, rCodeFormErr), nil
	}

	qType := binary.BigEndian.Uint16(req[offset : offset+2])
	qClass := binary.BigEndian.Uint16(req[offset+2 : offset+4])
	questionSection := req[12 : offset+4]

	tld := cfg.TLD
	if tld == "" {
		tld = names.DefaultTLD
	}
	lowerName := strings.ToLower(strings.TrimSuffix(qName, "."))
	// Per RFC 9462 §4.1, macOS mDNSResponder probes `_dns.resolver.arpa` (SVCB) to discover
	// Encrypted DNS. Returning NOERROR/NODATA cleanly terminates discovery without retries,
	// whereas arbitrary non-.alt domains receive REFUSED.
	isDDRProbe := lowerName == "_dns.resolver.arpa"
	if !isDDRProbe && !names.Contains(lowerName, tld) {
		return buildErrorResponse(txID, flags, questionSection, rCodeRefused), nil
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 60
	}

	var answer []byte
	if !isDDRProbe && qClass == qClassIN {
		switch qType {
		case qTypeA:
			if ip4 := cfg.IPv4Loopback.To4(); ip4 != nil {
				answer = buildResourceRecord(qTypeA, ttl, ip4)
			}
		case qTypeAAAA:
			if cfg.IPv6Loopback != nil && cfg.IPv6Loopback.To4() == nil {
				if ip16 := cfg.IPv6Loopback.To16(); ip16 != nil {
					answer = buildResourceRecord(qTypeAAAA, ttl, ip16)
				}
			}
		}
	}

	resp := make([]byte, 12, 12+len(questionSection)+len(answer))
	binary.BigEndian.PutUint16(resp[0:2], txID)

	// QR=1 (Response), AA=1 (Authoritative), copy RD bit, RA=0, RCODE=0
	rdBit := flags & 0x0100
	respFlags := uint16(0x8400) | rdBit | uint16(rCodeNoError)
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT = 1
	if len(answer) > 0 {
		binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT = 1
	} else {
		binary.BigEndian.PutUint16(resp[6:8], 0) // NODATA (0 answers, NOERROR)
	}
	binary.BigEndian.PutUint16(resp[8:10], 0)  // NSCOUNT = 0
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT = 0

	resp = append(resp, questionSection...)
	resp = append(resp, answer...)
	return resp, nil
}

func decodeQName(pkt []byte, start int) (string, int, error) {
	var labels []string
	idx := start
	for {
		if idx >= len(pkt) {
			return "", 0, ErrMalformedPacket
		}
		length := int(pkt[idx])
		idx++
		if length == 0 {
			break
		}
		if (length & 0xC0) != 0 {
			return "", 0, ErrMalformedPacket
		}
		if idx+length > len(pkt) {
			return "", 0, ErrMalformedPacket
		}
		labels = append(labels, string(pkt[idx:idx+length]))
		idx += length
	}
	return strings.Join(labels, "."), idx, nil
}

func buildResourceRecord(rrType uint16, ttl uint32, rdata []byte) []byte {
	rr := make([]byte, 12+len(rdata))
	// Name pointer to offset 12 (0xC00C)
	binary.BigEndian.PutUint16(rr[0:2], 0xC00C)
	binary.BigEndian.PutUint16(rr[2:4], rrType)
	binary.BigEndian.PutUint16(rr[4:6], qClassIN)
	binary.BigEndian.PutUint32(rr[6:10], ttl)
	binary.BigEndian.PutUint16(rr[10:12], uint16(len(rdata)))
	copy(rr[12:], rdata)
	return rr
}

func buildErrorResponse(txID, reqFlags uint16, question []byte, rcode uint8) []byte {
	resp := make([]byte, 12, 12+len(question))
	binary.BigEndian.PutUint16(resp[0:2], txID)
	rdBit := reqFlags & 0x0100
	respFlags := uint16(0x8000) | rdBit | uint16(rcode&0x0F)
	binary.BigEndian.PutUint16(resp[2:4], respFlags)
	if len(question) > 0 {
		binary.BigEndian.PutUint16(resp[4:6], 1)
	}
	resp = append(resp, question...)
	return resp
}

// ServeUDP runs a UDP DNS stub listener that processes queries via HandleQuery until ctx is cancelled
// or an unrecoverable PacketConn read error occurs.
func ServeUDP(ctx context.Context, conn net.PacketConn, cfg Config) error {
	if conn == nil {
		return errors.New("dnsstub: nil PacketConn")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		resp, err := HandleQuery(buf[:n], cfg)
		if err != nil || len(resp) == 0 {
			continue
		}
		_, _ = conn.WriteTo(resp, addr)
	}
}

// ServeTCP runs an RFC 1035 §4.2.2 length-prefixed TCP DNS stub listener so TCP fallback
// queries from macOS mDNSResponder, Chrome, or `dig +tcp` resolve identically to UDP.
func ServeTCP(ctx context.Context, ln net.Listener, cfg Config) error {
	if ln == nil {
		return errors.New("dnsstub: nil Listener")
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				continue
			}
			return err
		}
		go handleTCPConn(conn, cfg)
	}
}

func handleTCPConn(conn net.Conn, cfg Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var lenBuf [2]byte
	for {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen == 0 || msgLen > 4096 {
			return
		}
		req := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, req); err != nil {
			return
		}
		resp, err := HandleQuery(req, cfg)
		if err != nil || len(resp) == 0 || len(resp) > 65535 {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[0:2], uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// EncodeQuery constructs a minimal DNS query packet for testing and diagnostics (alt doctor).
func EncodeQuery(txID uint16, domain string, qType uint16) []byte {
	pkt := make([]byte, 12)
	binary.BigEndian.PutUint16(pkt[0:2], txID)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // Standard query with RD=1
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT=1

	trimmed := strings.TrimSuffix(domain, ".")
	for _, label := range strings.Split(trimmed, ".") {
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, []byte(label)...)
	}
	pkt = append(pkt, 0x00) // Root label

	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], qType)
	binary.BigEndian.PutUint16(tail[2:4], qClassIN)
	return append(pkt, tail...)
}
