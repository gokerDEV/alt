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
	"alt/pkg/dnsstub"
	"alt/pkg/names"
	"alt/pkg/pki"
	"alt/pkg/profile"
	"alt/pkg/resolver"
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
  setup                           Initialize device keys, local CA, .alt resolver, and loopback service (planned)
  login <github | key.pub>        Authenticate account via GitHub device flow or SSH key challenge (planned)
  dev <domain> [flags]            Start local development override (shadows network resolution locally)
  run [domain] [flags]            Run foreground loopback HTTPS proxy, optional DNS stub, and IPFS resolver
  publish <domain> [flags]        Publish local application over WebRTC P2P or update signed HTTPS target (planned)
  config validate <path>          Validate alt.yaml or network profile schema without applying changes
  register <domain.alt>           Register a .alt domain with atomic quota verification (planned)
  list                            List active local overrides, configured publications, and domain statuses
  halt <domain.alt>               Stop a local override/P2P session or publish a disabled HTTPS target record
  status                          Display resolver, CA, network, signaling, and active session status
  doctor                          Run port, DNS stub, OS trust store, and browser DoH diagnostics`)
}

// foregroundOptions holds parsed CLI flags for `alt run`.
type foregroundOptions struct {
	Domain       string
	Port         int
	ListenAddr   string
	DNSListen    string
	TLD          string
	ProfilePath  string
	StateDir     string
	ManifestCID  string
	ManifestFile string
	Gateways     string
}

func runForeground(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runForegroundWithContext(ctx, args, nil)
}

func runForegroundWithContext(ctx context.Context, args []string, readyCh chan<- foregroundRuntimeInfo) error {
	var domainArg string
	flagArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		domainArg = args[0]
		flagArgs = args[1:]
	}

	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	port := flags.Int("port", 0, "loopback HTTP upstream port for local override (optional if resolving via IPFS/profile)")
	listenAddr := flags.String("listen", "127.0.0.1:8443", "loopback HTTPS listen address")
	dnsListen := flags.String("dns-listen", "", "optional loopback UDP DNS listen address (e.g. 127.0.0.1:15353)")
	tldFlag := flags.String("tld", "", "private namespace TLD (defaults to profile TLD or 'alt')")
	profilePath := flags.String("profile", os.Getenv("ALT_PROFILE"), "path to versioned network profile YAML")
	stateDir := flags.String("state-dir", "", "directory for the device-local CA")
	manifestCID := flags.String("manifest-cid", "", "override manifest CIDv1 for IPFS gateway resolution")
	manifestFile := flags.String("manifest-file", "", "optional local content-addressed manifest fixture file")
	gatewaysCSV := flags.String("gateways", "", "comma-separated IPFS HTTP gateway URLs (overrides profile gateways)")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	prof, err := resolveNetworkProfile(*profilePath, *tldFlag)
	if err != nil {
		return err
	}

	if *manifestCID != "" {
		prof.Resolver.ManifestCID = strings.TrimSpace(*manifestCID)
	}
	if *gatewaysCSV != "" {
		parts := strings.Split(*gatewaysCSV, ",")
		gws := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				gws = append(gws, trimmed)
			}
		}
		prof.Resolver.Gateways = gws
	}
	if err := prof.Validate(); err != nil {
		return err
	}

	var normalizedDomain string
	if domainArg != "" {
		normalizedDomain, err = names.NormalizeDomain(domainArg, prof.TLD)
		if err != nil {
			return err
		}
	}

	hasLocalOverride := *port > 0
	if *port < 0 || *port > 65535 {
		return fmt.Errorf("--port must be between 1 and 65535")
	}
	if hasLocalOverride && normalizedDomain == "" {
		return fmt.Errorf("domain argument is required when --port is set (usage: alt run <domain> --port <port>)")
	}

	src, err := buildRecordSource(prof, *manifestFile)
	if err != nil {
		return err
	}
	if !hasLocalOverride && src == nil {
		return fmt.Errorf("usage: alt run <domain> --port <port> [flags] (or provide a network --profile / --manifest-file with IPFS resolver settings)")
	}

	listenIP, err := requireLoopbackListen(*listenAddr, "--listen")
	if err != nil {
		return err
	}

	var dnsConn net.PacketConn
	if *dnsListen != "" {
		if _, err := requireLoopbackListen(*dnsListen, "--dns-listen"); err != nil {
			return err
		}
		dnsConn, err = net.ListenPacket("udp", *dnsListen)
		if err != nil {
			return fmt.Errorf("listen UDP DNS on %s: %w", *dnsListen, err)
		}
		defer dnsConn.Close()
	}

	caDir := *stateDir
	if caDir == "" {
		configDir, err := os.UserConfigDir()
		if err != nil {
			return fmt.Errorf("resolve user config directory: %w", err)
		}
		caDir = filepath.Join(configDir, "alt", "networks", prof.NetworkID, "pki")
	}
	ca, err := pki.LoadOrCreateCAForTLD(caDir, prof.TLD)
	if err != nil {
		return err
	}

	res, err := resolver.NewChecked(resolver.Config{
		Profile: prof,
		Source:  src,
	})
	if err != nil {
		return fmt.Errorf("initialize resolver: %w", err)
	}
	engine, err := daemon.NewEngineChecked(daemon.Options{
		Profile:  prof,
		Resolver: res,
	})
	if err != nil {
		return fmt.Errorf("initialize daemon engine: %w", err)
	}

	if hasLocalOverride {
		site := config.SiteEntry{Routes: []config.RouteEntry{{
			Match:    "/*",
			Upstream: "http://127.0.0.1:" + strconv.Itoa(*port),
		}}}
		if err := engine.UpsertLocalSite(normalizedDomain, site, "."); err != nil {
			return fmt.Errorf("configure local route: %w", err)
		}
	}

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listenAddr, err)
	}
	actualHTTPSAddr := listener.Addr().String()

	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: ca.GetCertificate,
	})
	server := &http.Server{
		Handler:           engine,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	dnsCtx, cancelDNS := context.WithCancel(ctx)
	defer cancelDNS()

	dnsErrCh := make(chan error, 1)
	var actualDNSAddr string
	if dnsConn != nil {
		actualDNSAddr = dnsConn.LocalAddr().String()
		dnsCfg := dnsstub.Config{
			TTL: 60,
			TLD: prof.TLD,
		}
		if ip4 := listenIP.To4(); ip4 != nil {
			dnsCfg.IPv4Loopback = ip4
		} else {
			dnsCfg.IPv6Loopback = listenIP
		}
		go func() {
			dnsErrCh <- dnsstub.ServeUDP(dnsCtx, dnsConn, dnsCfg)
		}()
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(tlsListener)
	}()

	certPath := filepath.Join(caDir, "ca.crt")
	targetDisplayDomain := normalizedDomain
	if targetDisplayDomain == "" {
		targetDisplayDomain = "register." + prof.TLD
	}

	fmt.Printf("ALT foreground proxy is running\n")
	fmt.Printf("  Network:  %s (.%s)\n", prof.NetworkID, prof.TLD)
	fmt.Printf("  URL:      https://%s%s\n", targetDisplayDomain, displayPort(actualHTTPSAddr))
	if hasLocalOverride {
		fmt.Printf("  Override: http://127.0.0.1:%d (shadows network resolution locally)\n", *port)
	} else {
		fmt.Printf("  Mode:     verified IPFS/manifest record resolution\n")
	}
	if actualDNSAddr != "" {
		fmt.Printf("  DNS Stub: udp://%s (authoritative for .%s only)\n", actualDNSAddr, prof.TLD)
	}
	fmt.Printf("  CA:       %s\n", certPath)
	fmt.Printf("  Test:     curl --resolve %s:%s:%s --cacert %s https://%s%s/\n",
		targetDisplayDomain, listenPort(actualHTTPSAddr), listenIP.String(), certPath, targetDisplayDomain, displayPort(actualHTTPSAddr))
	fmt.Println("This command does not modify DNS, the system trust store, or launchd. Press Ctrl-C to stop.")

	if readyCh != nil {
		readyCh <- foregroundRuntimeInfo{
			HTTPSAddr: actualHTTPSAddr,
			DNSAddr:   actualDNSAddr,
			CertPath:  certPath,
			NetworkID: prof.NetworkID,
			TLD:       prof.TLD,
			DNSConn:   dnsConn,
		}
	}

	select {
	case <-ctx.Done():
		cancelDNS()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down HTTPS server: %w", err)
		}
		return nil
	case err := <-dnsErrCh:
		cancelDNS()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if err == nil {
			return nil
		}
		return fmt.Errorf("DNS stub stopped unexpectedly: %w", err)
	case err := <-serveErr:
		cancelDNS()
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

type foregroundRuntimeInfo struct {
	HTTPSAddr string
	DNSAddr   string
	CertPath  string
	NetworkID string
	TLD       string
	DNSConn   net.PacketConn
}

func resolveNetworkProfile(profilePath, tldOverride string) (*profile.Profile, error) {
	if strings.TrimSpace(profilePath) != "" {
		prof, err := profile.LoadFile(profilePath)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(tldOverride) != "" {
			normTLD, err := names.NormalizeTLD(tldOverride)
			if err != nil {
				return nil, err
			}
			if normTLD != prof.TLD {
				return nil, fmt.Errorf("--tld %q conflicts with network profile TLD %q", normTLD, prof.TLD)
			}
		}
		return prof, nil
	}

	if strings.TrimSpace(tldOverride) != "" {
		return profile.ForLocalTLD(tldOverride)
	}
	return profile.Default(), nil
}

func buildRecordSource(prof *profile.Profile, manifestFile string) (resolver.RecordSource, error) {
	if strings.TrimSpace(manifestFile) != "" {
		return resolver.LoadFixtureSourceFile(manifestFile, prof.Resolver.ManifestCID, prof.NetworkID)
	}
	if prof.Resolver.ManifestCID != "" && len(prof.Resolver.Gateways) > 0 {
		return resolver.NewGatewaySource(resolver.GatewayOptions{
			ManifestCID:     prof.Resolver.ManifestCID,
			ExpectedNetwork: prof.NetworkID,
			Gateways:        prof.Resolver.Gateways,
		})
	}
	return nil, nil
}

func requireLoopbackListen(addr, flagName string) (net.IP, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid %s address: %w", flagName, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%s must use an explicit loopback IP address", flagName)
	}
	return ip, nil
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
		return fmt.Errorf("usage: alt config validate [path/to/alt.yaml] [--profile path/to/profile.yaml] [--tld alt]")
	}

	flags := flag.NewFlagSet("config validate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	profilePath := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	tldFlag := flags.String("tld", "", "private namespace TLD")

	var positional []string
	var flagTokens []string
	for i := 1; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagTokens = append(flagTokens, args[i:]...)
			break
		}
		positional = append(positional, args[i])
	}
	if err := flags.Parse(flagTokens); err != nil {
		return err
	}
	path := "alt.yaml"
	if len(positional) >= 1 {
		path = positional[0]
	}

	prof, err := resolveNetworkProfile(*profilePath, *tldFlag)
	if err != nil {
		return err
	}

	cfg, err := config.LoadFileForTLD(path, prof.TLD)
	if err != nil {
		return err
	}
	fmt.Printf("OK: %s is valid for network %s (.%s) (version %d, %d site(s) defined)\n",
		path, prof.NetworkID, prof.TLD, cfg.Version, len(cfg.Sites))
	return nil
}

func normalizeCLIDomain(name string) string {
	prof, err := resolveNetworkProfile(os.Getenv("ALT_PROFILE"), "")
	if err != nil {
		prof = profile.Default()
	}
	n, err := names.NormalizeDomain(name, prof.TLD)
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
	fmt.Println("alt setup: privileged OS installer is planned and intentionally out of scope for the non-privileged demo slice; use `alt run` for foreground local HTTPS.")
	return nil
}

func runLogin(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt login <github | ~/.ssh/id_ed25519.pub>")
	}
	fmt.Printf("alt login: account authentication via %s is planned (non-goal in current demo slice).\n", args[0])
	return nil
}

func runPublish(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt publish <domain.alt> [--port <p> | --target <https://...> | --config <file>]")
	}
	domain := normalizeCLIDomain(args[0])
	fmt.Printf("alt publish: network publication workflow for %s is planned; use cmd/alt-bootstrap-gen for signed demo manifests.\n", domain)
	return nil
}

func runRegister(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: alt register <domain.alt>")
	}
	domain := normalizeCLIDomain(args[0])
	fmt.Printf("alt register: hosted registration for %s is planned.\n", domain)
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
	prof, err := resolveNetworkProfile(os.Getenv("ALT_PROFILE"), "")
	if err != nil {
		return err
	}
	fmt.Printf("ALT Network Profile: %s (.%s)\n", prof.NetworkID, prof.TLD)
	return nil
}

func runDoctor(args []string) error {
	fmt.Println("ALT Doctor Diagnostics (demo slice):")
	fmt.Println("  [1/4] Local DNS stub (--dns-listen):    available via `alt run`")
	fmt.Println("  [2/4] OS resolver (/etc/resolver/alt):  manual one-time setup (not modified automatically)")
	fmt.Println("  [3/4] Device Root CA trust store:       user-scoped CA generated per network profile")
	fmt.Println("  [4/4] Browser DoH fallback probe:       unverified (requires browser probe)")
	return nil
}
