package dcnet_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"alt/pkg/p2p/dcnet"
)

func TestChannelBudgetAndSessionClose(t *testing.T) {
	visitorSess, publisherSess := createLinkedSessions(t)
	defer visitorSess.Close()
	defer publisherSess.Close()

	// Drain accepted connections on publisher side
	go func() {
		for {
			conn, err := publisherSess.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
		}
	}()

	ctx := context.Background()
	conns := make([]interface{ Close() error }, 0, dcnet.MaxActiveChannels)

	// Open exactly MaxActiveChannels (16) concurrent channels
	for i := 0; i < dcnet.MaxActiveChannels; i++ {
		c, err := visitorSess.DialContext(ctx, "tcp", "goker.alt:80")
		if err != nil {
			t.Fatalf("expected dial %d to succeed, got: %v", i+1, err)
		}
		conns = append(conns, c)
	}

	// The 17th dial must block and time out when all 16 slots are occupied
	shortCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := visitorSess.DialContext(shortCtx, "tcp", "goker.alt:80"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected 17th channel dial to fail with DeadlineExceeded, got: %v", err)
	}

	// Closing one channel releases a slot so a new dial succeeds
	_ = conns[0].Close()
	dialCtx, dialCancel := context.WithTimeout(ctx, 2*time.Second)
	defer dialCancel()
	extraConn, err := visitorSess.DialContext(dialCtx, "tcp", "goker.alt:80")
	if err != nil {
		t.Fatalf("expected dial after releasing slot to succeed, got: %v", err)
	}
	_ = extraConn.Close()

	// Closing the session rejects subsequent dials with ErrSessionClosed
	_ = visitorSess.Close()
	if _, err := visitorSess.DialContext(ctx, "tcp", "goker.alt:80"); !errors.Is(err, dcnet.ErrSessionClosed) {
		t.Fatalf("expected ErrSessionClosed after session close, got: %v", err)
	}
}

func TestWriteDeadlineUnblocksBackpressure(t *testing.T) {
	visitorSess, publisherSess := createLinkedSessions(t)
	defer visitorSess.Close()
	defer publisherSess.Close()

	// Publisher accepts connection but never reads, causing SCTP/DataChannel send buffer to fill up
	accepted := make(chan struct{})
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := publisherSess.Accept()
		if err != nil {
			return
		}
		close(accepted)
		<-done
		_ = conn.Close()
	}()

	conn, err := visitorSess.DialContext(context.Background(), "tcp", "goker.alt:80")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	defer conn.Close()
	<-accepted

	// Set a short write deadline and write a large payload that exceeds the 256 KiB ceiling
	_ = conn.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	huge := make([]byte, 2*1024*1024)
	_, err = conn.Write(huge)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded when blocked on backpressure, got: %v", err)
	}
}

func TestMultipleKeepAliveRequestsReuseChannel(t *testing.T) {
	visitorSess, publisherSess := createLinkedSessions(t)
	defer visitorSess.Close()
	defer publisherSess.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("pong"))
	})

	srv := &http.Server{Handler: mux}
	go func() {
		_ = srv.Serve(publisherSess)
	}()
	defer srv.Close()

	client := &http.Client{Transport: visitorSess.Transport()}
	for i := 0; i < 5; i++ {
		resp, err := client.Get("http://goker.alt/ping")
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		_ = resp.Body.Close()
	}
}
