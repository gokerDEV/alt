package dcnet_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"alt/pkg/p2p/dcnet"
	"github.com/pion/webrtc/v4"
)

func createLinkedSessions(t *testing.T) (*dcnet.Session, *dcnet.Session) {
	t.Helper()

	se := webrtc.SettingEngine{}
	se.DetachDataChannels()
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))

	visitorPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	publisherPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}

	visitorPC.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = publisherPC.AddICECandidate(c.ToJSON())
		}
	})
	publisherPC.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c != nil {
			_ = visitorPC.AddICECandidate(c.ToJSON())
		}
	})

	// Bootstrap SCTP association with a control channel
	_, err = visitorPC.CreateDataChannel("bootstrap", nil)
	if err != nil {
		t.Fatal(err)
	}

	offer, err := visitorPC.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := visitorPC.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	if err := publisherPC.SetRemoteDescription(offer); err != nil {
		t.Fatal(err)
	}
	answer, err := publisherPC.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisherPC.SetLocalDescription(answer); err != nil {
		t.Fatal(err)
	}
	if err := visitorPC.SetRemoteDescription(answer); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	return dcnet.NewSession(ctx, visitorPC), dcnet.NewSession(ctx, publisherPC)
}

func TestSlowReaderBackpressureAndIntegrity(t *testing.T) {
	visitorSess, publisherSess := createLinkedSessions(t)
	defer visitorSess.Close()
	defer publisherSess.Close()

	// 2 MiB payload (> 256 KiB buffer ceiling to force multiple backpressure cycles)
	payload := make([]byte, 2*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})

	pubServer := &http.Server{Handler: mux}
	go func() {
		_ = pubServer.Serve(publisherSess)
	}()
	defer pubServer.Close()

	targetURL, _ := url.Parse("http://goker.alt")
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.Transport = visitorSess.Transport()

	req, err := http.NewRequest(http.MethodGet, "http://goker.alt/stream", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := visitorSess.Transport().RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	// Simulate slow reader with small 4 KiB reads to exercise readBuf + write backpressure
	var received bytes.Buffer
	smallBuf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(smallBuf)
		if n > 0 {
			received.Write(smallBuf[:n])
			time.Sleep(1 * time.Millisecond)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
	}

	if !bytes.Equal(payload, received.Bytes()) {
		t.Fatalf("byte integrity mismatch: expected %d bytes, got %d bytes", len(payload), received.Len())
	}
}

