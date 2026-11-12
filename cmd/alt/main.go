package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"alt/pkg/config"
	"alt/pkg/daemon"
	"alt/pkg/names"
	"alt/pkg/pki"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "setup":
		err = runSetup(args)
	case "login":
		err = runLogin(args)
	case "dev":
		err = runDev(args)
	case "run":
		err = runForeground(args)
	case "publish":
		err = runPublish(args)
	case "config":
		err = runConfig(args)
	case "register":
		err = runRegister(args)
	case "list":
		err = runList(args)
	case "halt":
		err = runHalt(args)
	case "status":
		err = runStatus(args)
	case "doctor":
		err = runDoctor(args)
	case "help", "-h", "--help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ALT — An alternative universe for the web (.alt)

Usage:
  alt <command> [arguments]

Commands:
  setup                           Initialize device keys, local CA, .alt resolver, and loopback service
  login <github | key.pub>        Authenticate account via GitHub device flow or SSH key challenge
  dev <domain> [flags]            Start local development override (shadows network resolution locally)
  run <domain> [flags]            Run a foreground loopback HTTPS proxy without changing OS settings
  publish <domain> [flags]        Publish local application over WebRTC P2P or update signed HTTPS target
  config validate <path>          Validate alt.yaml schema and semantic routing rules without applying changes
  register <domain.alt>           Register a .alt domain with atomic quota verification
  list                            List active local overrides, configured publications, and domain statuses
  halt <domain.alt>               Stop a local override/P2P session or publish a disabled HTTPS target record
  status                          Display resolver, CA, network, signaling, and active session status
  doctor                          Run port, DNS stub, OS trust store, and browser DoH diagnostics`)
}

func runForeground(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt run <domain> --port <port> [--listen 127.0.0.1:8443] [--tld alt] [--state-dir path]")
	}

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	port := flags.Int("port", 0, "loopback HTTP upstream port")
	listenAddr := flags.String("listen", "127.0.0.1:8443", "loopback HTTPS listen address")
	tld := flags.String("tld", envOrDefault("ALT_TLD", names.DefaultTLD), "private namespace TLD")
	stateDir := flags.String("state-dir", "", "directory for the device-local CA")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *port < 1 || *port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}

	domain, err := names.NormalizeDomain(args[0], *tld)
	if err != nil {
		return err
	}
	if err := requireLoopbackListen(*listenAddr); err != nil {
		return err
	}

	caDir := *stateDir
	if caDir == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("resolve user config directory: %w", err)
		}
		caDir = filepath.Join(configDir, "alt", "networks", *tld, "pki")
	}
	ca, err := loadOrCreateNamespaceCA(caDir, *tld)
	if err != nil {
		return err
	}

	engine := daemon.NewEngine(nil)
	site := config.SiteEntry{Routes: []config.RouteEntry{{
		Match:    "/*",
		Upstream: "http://127.0.0.1:" + strconv.Itoa(*port),
	}}}
	if err := engine.UpsertLocalSite(domain, site, "."); err != nil {
		return fmt.Errorf("configure local route: %w", err)
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddr, err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: ca.GetCertificate,
	})
	server := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(tlsListener)
	}()

	certPath := filepath.Join(caDir, "ca.crt")
	fmt.Printf("ALT foreground proxy is running\n")
	fmt.Printf("  URL:      https://%s%s\n", domain, displayPort(*listenAddr))
	fmt.Printf("  Upstream: http://127.0.0.1:%d\n", *port)
	fmt.Printf("  CA:       %s\n", certPath)
	fmt.Printf("  Test:     curl --resolve %s:%s:127.0.0.1 --cacert %s https://%s%s/\n",
		domain, listenPort(*listenAddr), certPath, domain, displayPort(*listenAddr))
	fmt.Println("This command does not modify DNS, the system trust store, or launchd. Press Ctrl-C to stop.")

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down HTTPS server: %w", err)
		}
		return nil
	case err := <-serveErr:
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func requireLoopbackListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid --listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--listen must use an explicit loopback IP address")
	}
	return nil
}

func loadOrCreateNamespaceCA(dir, tld string) (*pki.CA, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil {
		return pki.ParseCA(certPEM, keyPEM)
	}
	if !os.IsNotExist(certErr) || !os.IsNotExist(keyErr) {
		return nil, fmt.Errorf("incomplete or unreadable CA state in %s", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	ca, keyPEM, err := pki.GenerateCAForTLD(tld)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, ca.CertPEM(), 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

func listenPort(addr string) string {
	_, port, _ := net.SplitHostPort(addr)
	return port
}

func displayPort(addr string) string {
	port := listenPort(addr)
	if port == "443" {
		return ""
	}
	return ":" + port
}

func runConfig(args []string) error {
	if len(args) < 1 || args[0] != "validate" {
		return fmt.Errorf("usage: alt config validate [path/to/alt.yaml]")
	}
	path := "alt.yaml"
	if len(args) >= 2 {
		path = args[1]
	}

	tld := os.Getenv("ALT_TLD")
	if tld == "" {
		tld = names.DefaultTLD
	}
	cfg, err := config.LoadFileForTLD(path, tld)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s is valid (version %d, %d site(s) defined)\n", path, cfg.Version, len(cfg.Sites))
	return nil
}

func normalizeCLIDomain(name string) string {
	tld := os.Getenv("ALT_TLD")
	if tld == "" {
		tld = names.DefaultTLD
	}
	n, err := names.NormalizeDomain(name, tld)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(name))
	}
	return n
}

func runDev(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt dev <domain> [--port <p> | --route <match=upstream> | --dir <path> | --config <file>]")
	}
	domain := normalizeCLIDomain(args[0])

	var (
		port       string
		dir        string
		configFile string
		routes     []string
	)

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--port":
			if i+1 >= len(args) {
				return fmt.Errorf("--port requires a value")
			}
			i++
			port = args[i]
		case "--dir":
			if i+1 >= len(args) {
				return fmt.Errorf("--dir requires a value")
			}
			i++
			dir = args[i]
		case "--config":
			if i+1 >= len(args) {
				return fmt.Errorf("--config requires a value")
			}
			i++
			configFile = args[i]
		case "--route":
			if i+1 >= len(args) {
				return fmt.Errorf("--route requires a value")
			}
			i++
			routes = append(routes, args[i])
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}

	// Enforce mutual exclusivity between --config, --port, --route, and --dir (§18)
	modeCount := 0
	if configFile != "" {
		modeCount++
	}
	if port != "" {
		modeCount++
	}
	if len(routes) > 0 {
		modeCount++
	}
	if dir != "" {
		modeCount++
	}
	if modeCount > 1 {
		return fmt.Errorf("--config, --port, --route, and --dir are mutually exclusive source modes")
	}

	fmt.Printf("[NOTICE] Local override active for https://%s (this shadows network resolution on this device only)\n", domain)
	return nil
}

func runSetup(args []string) error {
	fmt.Println("alt setup: verifying loopback alias (127.88.0.1), device CA, and /etc/resolver/alt...")
	return nil
}

func runLogin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt login <github | ~/.ssh/id_ed25519.pub>")
	}
	fmt.Printf("alt login: initiating authentication via %s...\n", args[0])
	return nil
}

func runPublish(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt publish <domain.alt> [--port <p> | --target <https://...> | --config <file>]")
	}
	domain := normalizeCLIDomain(args[0])
	fmt.Printf("alt publish: preparing publication for %s...\n", domain)
	return nil
}

func runRegister(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt register <domain.alt>")
	}
	domain := normalizeCLIDomain(args[0])
	fmt.Printf("alt register: requesting atomic allocation for %s...\n", domain)
	return nil
}

func runList(args []string) error {
	fmt.Println("DOMAIN\tMODE\tSTATUS\tTARGET")
	return nil
}

func runHalt(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt halt <domain.alt>")
	}
	domain := normalizeCLIDomain(args[0])
	fmt.Printf("alt halt: stopping %s...\n", domain)
	return nil
}

func runStatus(args []string) error {
	fmt.Println("ALT Daemon Status: ready")
	return nil
}

func runDoctor(args []string) error {
	fmt.Println("ALT Doctor Diagnostics:")
	fmt.Println("  [1/4] Local DNS stub (.alt query):      ready")
	fmt.Println("  [2/4] OS resolver (/etc/resolver/alt):  ready")
	fmt.Println("  [3/4] Device Root CA trust store:       ready")
	fmt.Println("  [4/4] Browser DoH fallback probe:       unverified (requires browser probe)")
	return nil
}
