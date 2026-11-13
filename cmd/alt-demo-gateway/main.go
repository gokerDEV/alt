// Command alt-demo-gateway serves a deterministic loopback IPFS HTTP gateway
// (/ipfs/<cid>?format=raw) for local end-to-end testing when a Kubo IPFS node
// is not running on the developer machine.
package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"alt/pkg/resolver"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:18080", "loopback HTTP address to serve /ipfs/<cid>")
	manifestPath := flag.String("manifest", "examples/demo-bootstrap/manifest.json", "path to raw manifest file")
	flag.Parse()

	host, _, err := net.SplitHostPort(*listenAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		fmt.Fprintln(os.Stderr, "Error: --listen must be an explicit loopback IP:port")
		os.Exit(1)
	}

	raw, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading manifest: %v\n", err)
		os.Exit(1)
	}
	cid := resolver.ComputeRawCIDv1(raw)

	mux := http.NewServeMux()
	mux.HandleFunc("/ipfs/", func(w http.ResponseWriter, r *http.Request) {
		requested := strings.TrimPrefix(r.URL.Path, "/ipfs/")
		if requested != cid {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.ipld.raw")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	})

	fmt.Printf("ALT loopback IPFS block server ready\n")
	fmt.Printf("  Gateway:  http://%s\n", *listenAddr)
	fmt.Printf("  CIDv1:    %s\n", cid)
	fmt.Printf("  Endpoint: http://%s/ipfs/%s?format=raw\n", *listenAddr, cid)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
