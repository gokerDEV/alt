package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
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
	"alt/pkg/sysinstall"
)

// Build-time metadata injected via -ldflags "-X main.Version=... -X main.Commit=... -X main.BuildDate=..."
var (
	Version   = "0.2.0"
	Commit    = "dev"
	BuildDate = "unknown"
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
	case "uninstall":
		err = runUninstall(args)
	case "daemon":
		err = runDaemonSubcommand(args)
	case "login":
		err = runLogin(args)
	case "logout":
		err = runLogout(args)
	case "account":
		err = runAccount(args)
	case "dev":
		err = runDev(args)
	case "run":
		err = runForeground(args)
	case "publish":
		err = runPublish(args)
	case "config":
		err = runConfig(args)
	case "profile":
		err = runProfileSubcommand(args)
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
	case "version", "-v", "--version":
		err = runVersion(args)
	case "completion":
		err = runCompletion(args)
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
	fmt.Println(`ALT — Local-first HTTPS development and signed name resolution (.alt)

Usage:
  alt <command> [arguments]

Commands:
  setup [flags]                   Install macOS .alt resolver, local CA trust, lo0 alias, PF port 443 rule, and LaunchAgent
  uninstall [flags]               Cleanly remove macOS .alt resolver, PF rule, lo0 alias, CA trust, and LaunchAgent
  daemon <start|stop|reload|status> Manage the background ALT daemon directly
  login github [flags]            Authenticate account via GitHub Device Flow and exchange ALT CLI session
  logout                          Revoke server CLI session and remove local token
  account                         Show authenticated GitHub account, bound owner key, and .alt domain status
  dev [domain] [flags]            Configure and persist local development override (--port, --dir, --route, or --config)
  run [domain] [flags]            Run foreground/daemon loopback HTTPS proxy, DNS stub, IPC socket, and IPFS/IPNS resolver
  publish <domain> --target <url> Sign and publish an HTTPS target record (alt.target.v1) for your .alt domain
  config validate [path]          Validate alt.yaml or network profile schema without applying changes
  profile <show|update> [flags]   Inspect or apply a signed trust-root / network profile bundle update
  register <domain.alt>           Bind local Ed25519 owner key and register a .alt domain
  list [--json]                   List active local overrides, persisted routes, and published domain status
  halt <domain.alt | --all>       Remove a local override from the daemon and persistent state
  status [--json]                 Display live daemon, resolver cache, IPNS watermark, CA, and network status
  doctor [--json]                 Execute live DNS stub, /etc/resolver, CA X.509 constraint, and port 443 coexistence checks
  version [--json]                Print version, commit, build date, and target architecture
  completion <zsh|bash|fish>      Generate shell completion script`)
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
	dnsListen := flags.String("dns-listen", "", "optional loopback UDP DNS listen address (e.g. 127.0.0.2:15353)")
	tldFlag := flags.String("tld", "", "private namespace TLD (defaults to profile TLD or 'alt')")
	profilePath := flags.String("profile", os.Getenv("ALT_PROFILE"), "path to versioned network profile YAML")
	stateDirFlag := flags.String("state-dir", "", "directory for daemon state, IPC socket, resolver cache, and PKI")
	manifestCID := flags.String("manifest-cid", "", "override manifest CIDv1 for IPFS gateway resolution")
	ipnsRoot := flags.String("ipns-root", "", "override self-certifying k51... IPNS root for resolution")
	manifestFile := flags.String("manifest-file", "", "optional local content-addressed manifest fixture file")
	gatewaysCSV := flags.String("gateways", "", "comma-separated IPFS HTTP gateway URLs (overrides profile gateways)")
	daemonMode := flags.Bool("daemon", false, "run as persistent background daemon with single-instance flock and rotating logs")
	configFile := flags.String("config", "", "optional alt.yaml file to load into local overrides at startup")
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	prof, err := resolveNetworkProfileWithState(*profilePath, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	if *manifestCID != "" {
		prof.Resolver.ManifestCID = strings.TrimSpace(*manifestCID)
		if *ipnsRoot == "" {
			prof.Resolver.IPNSRoot = ""
		}
	}
	if *ipnsRoot != "" {
		prof.Resolver.IPNSRoot = strings.TrimSpace(*ipnsRoot)
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

	baseStateDir, caDir, err := resolveRuntimeAndPKIDirs(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	// Open persistent monotonic anti-rollback state store for the resolver
	resStatePath := filepath.Join(baseStateDir, "resolver-state.json")
	resStore, err := resolver.OpenStateStore(resStatePath, prof.NetworkID)
	if err != nil {
		return fmt.Errorf("open resolver state store: %w", err)
	}

	src, err := buildRecordSourceWithStore(prof, *manifestFile, resStore)
	if err != nil {
		return err
	}
	if !hasLocalOverride && src == nil && !*daemonMode {
		return fmt.Errorf("usage: alt run <domain> --port <port> [flags] (or provide a network --profile / --manifest-file with IPFS resolver settings)")
	}

	listenIP, err := requireLoopbackListen(*listenAddr, "--listen")
	if err != nil {
		return err
	}

	var instanceLock *daemon.InstanceLock
	sockPath, err := daemon.ResolveSocketPath(baseStateDir)
	if err != nil {
		return err
	}
	if *daemonMode {
		instanceLock, err = daemon.AcquireInstanceLock(baseStateDir, prof.NetworkID, sockPath)
		if err != nil {
			return err
		}
		defer instanceLock.Release()
	}

	var logWriter *daemon.RotatingLogWriter
	var daemonLogger *log.Logger
	if *daemonMode {
		logWriter, err = daemon.NewRotatingLogWriter(filepath.Join(baseStateDir, "logs", "daemon.log"), 0, 0)
		if err == nil {
			defer logWriter.Close()
			daemonLogger = log.New(logWriter, "[alt-daemon] ", log.LstdFlags|log.LUTC)
			defer func() {
				if rec := recover(); rec != nil {
					daemonLogger.Printf("CRASH PANIC: %v\n%s", rec, string(debug.Stack()))
					panic(rec)
				}
			}()
		}
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

	ca, err := pki.LoadOrCreateCAForTLD(caDir, prof.TLD)
	if err != nil {
		return err
	}

	res, err := resolver.NewChecked(resolver.Config{
		Profile:    prof,
		Source:     src,
		StateStore: resStore,
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

	daemonStore, err := daemon.OpenDaemonStateStore(filepath.Join(baseStateDir, "daemon-state.json"), prof.NetworkID, prof.TLD)
	if err != nil {
		return fmt.Errorf("open daemon state store: %w", err)
	}
	if err := daemon.RestoreSitesIntoEngine(engine, daemonStore); err != nil {
		return err
	}

	if strings.TrimSpace(*configFile) != "" {
		absCfg, err := filepath.Abs(*configFile)
		if err != nil {
			return err
		}
		loadedCfg, err := config.LoadFileForTLD(absCfg, prof.TLD)
		if err != nil {
			return err
		}
		cfgBaseDir := filepath.Dir(absCfg)
		var batch []daemon.PersistedSiteOverride
		for d, entry := range loadedCfg.Sites {
			if err := engine.UpsertLocalSite(d, entry, cfgBaseDir); err != nil {
				return err
			}
			batch = append(batch, daemon.PersistedSiteOverride{
				Domain:     d,
				SourceMode: "config",
				BaseDir:    cfgBaseDir,
				ConfigFile: absCfg,
				Entry:      entry,
			})
		}
		if err := daemonStore.Upsert(batch, absCfg); err != nil {
			return err
		}
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
		ErrorLog:          daemonLogger,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()

	dnsErrCh := make(chan error, 2)
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
		if dnsTCPLn, tcpErr := net.Listen("tcp", actualDNSAddr); tcpErr == nil {
			defer dnsTCPLn.Close()
			go func() {
				dnsErrCh <- dnsstub.ServeTCP(runCtx, dnsTCPLn, dnsCfg)
			}()
		}
		go func() {
			dnsErrCh <- dnsstub.ServeUDP(runCtx, dnsConn, dnsCfg)
		}()
	}

	certPath := filepath.Join(caDir, "ca.crt")
	var logFilePath string
	if logWriter != nil {
		logFilePath = logWriter.Path()
	}

	// Start Unix socket IPC server when no conflicting lock is held
	var ipcSrv *daemon.IPCServer
	var advisoryLock *daemon.InstanceLock
	if instanceLock == nil {
		advisoryLock = tryAcquireAdvisoryLock(baseStateDir, prof.NetworkID, sockPath)
		if advisoryLock != nil {
			defer advisoryLock.Release()
		}
	}
	if instanceLock != nil || advisoryLock != nil {
		ipcSrv, _ = daemon.StartIPCServer(daemon.IPCServerConfig{
			Engine:      engine,
			StateStore:  daemonStore,
			StateDir:    baseStateDir,
			SocketPath:  sockPath,
			StartedAt:   time.Now().UTC(),
			Version:     Version,
			HTTPSAddr:   actualHTTPSAddr,
			DNSAddr:     actualDNSAddr,
			LoopbackIP:  listenIP.String(),
			CACertPath:  certPath,
			LogFilePath: logFilePath,
			ShutdownFn:  cancelRun,
		})
		if ipcSrv != nil {
			defer ipcSrv.Close()
		}
	}
	if daemonLogger != nil {
		daemonLogger.Printf("started network=%s tld=%s https=%s dns=%s ipc=%s version=%s",
			prof.NetworkID, prof.TLD, actualHTTPSAddr, actualDNSAddr, sockPath, Version)
		defer daemonLogger.Printf("stopped network=%s", prof.NetworkID)
	}

	// Support SIGHUP live reload of tracked `alt.yaml` files
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	defer signal.Stop(sighupCh)
	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case <-sighupCh:
				if ipcSrv != nil {
					if res, rErr := ipcSrv.ReloadTrackedConfigs(); daemonLogger != nil {
						if rErr != nil {
							daemonLogger.Printf("SIGHUP reload failed: %v", rErr)
						} else {
							daemonLogger.Printf("SIGHUP reloaded %d config(s), %d active site(s)", len(res.ReloadedConfigs), res.ActiveSites)
						}
					}
				}
			}
		}
	}()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(tlsListener)
	}()

	targetDisplayDomain := normalizedDomain
	if targetDisplayDomain == "" {
		targetDisplayDomain = "register." + prof.TLD
	}

	fmt.Printf("ALT proxy is running\n")
	fmt.Printf("  Network:  %s (.%s)\n", prof.NetworkID, prof.TLD)
	fmt.Printf("  URL:      https://%s%s\n", targetDisplayDomain, displayPort(actualHTTPSAddr))
	if hasLocalOverride {
		fmt.Printf("  Override: http://127.0.0.1:%d (shadows network resolution locally)\n", *port)
	} else {
		fmt.Printf("  Mode:     verified IPFS/IPNS record resolution (%d local override(s))\n", len(engine.ListLocalSites()))
	}
	if actualDNSAddr != "" {
		fmt.Printf("  DNS Stub: udp://%s (authoritative for .%s only)\n", actualDNSAddr, prof.TLD)
	}
	if ipcSrv != nil {
		fmt.Printf("  IPC:      unix://%s\n", ipcSrv.SocketPath())
	}
	fmt.Printf("  CA:       %s\n", certPath)
	fmt.Printf("  Test:     curl --resolve %s:%s:%s --cacert %s https://%s%s/\n",
		targetDisplayDomain, listenPort(actualHTTPSAddr), listenIP.String(), certPath, targetDisplayDomain, displayPort(actualHTTPSAddr))
	if !*daemonMode {
		fmt.Println("This command does not modify DNS, the system trust store, or launchd. Press Ctrl-C to stop.")
	}

	if readyCh != nil {
		readyCh <- foregroundRuntimeInfo{
			HTTPSAddr:  actualHTTPSAddr,
			DNSAddr:    actualDNSAddr,
			CertPath:   certPath,
			NetworkID:  prof.NetworkID,
			TLD:        prof.TLD,
			DNSConn:    dnsConn,
			StateDir:   baseStateDir,
			SocketPath: sockPath,
		}
	}

	select {
	case <-runCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shut down HTTPS server: %w", err)
		}
		return nil
	case err := <-dnsErrCh:
		cancelRun()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if err == nil {
			return nil
		}
		return fmt.Errorf("DNS stub stopped unexpectedly: %w", err)
	case err := <-serveErr:
		cancelRun()
		if err == nil || err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

func tryAcquireAdvisoryLock(stateDir, networkID, sockPath string) *daemon.InstanceLock {
	lk, err := daemon.AcquireInstanceLock(stateDir, networkID, sockPath)
	if err != nil {
		return nil
	}
	return lk
}

type foregroundRuntimeInfo struct {
	HTTPSAddr  string
	DNSAddr    string
	CertPath   string
	NetworkID  string
	TLD        string
	DNSConn    net.PacketConn
	StateDir   string
	SocketPath string
}

// resolveRuntimeAndPKIDirs preserves backward compatibility with tests that pass `--state-dir` expecting
// `ca.key` and `ca.crt` directly in `--state-dir`, while placing default user runs under `<config>/alt/networks/<id>`.
func resolveRuntimeAndPKIDirs(stateDirFlag, networkID string) (baseStateDir string, caDir string, err error) {
	if strings.TrimSpace(stateDirFlag) != "" {
		abs, err := filepath.Abs(stateDirFlag)
		if err != nil {
			return "", "", err
		}
		// If `--state-dir` already has a `pki/` subdirectory from `alt setup`, use it; otherwise keep CA at root for test compatibility.
		subPKI := filepath.Join(abs, "pki")
		if st, err := os.Stat(subPKI); err == nil && st.IsDir() {
			return abs, subPKI, nil
		}
		return abs, abs, nil
	}
	base, err := resolveStateBaseDir("", networkID)
	if err != nil {
		return "", "", err
	}
	return base, filepath.Join(base, "pki"), nil
}

func resolveNetworkProfile(profilePath, tldOverride string) (*profile.Profile, error) {
	return resolveNetworkProfileWithState(profilePath, tldOverride, "")
}

func resolveNetworkProfileWithState(profilePath, tldOverride, stateDirFlag string) (*profile.Profile, error) {
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

	if strings.TrimSpace(tldOverride) != "" && !strings.EqualFold(strings.TrimSpace(tldOverride), names.DefaultTLD) {
		return profile.ForLocalTLD(tldOverride)
	}

	// Check if a signed profile bundle update was persisted in the default state directory
	stateDir, err := resolveStateBaseDir(stateDirFlag, profile.DefaultNetworkID)
	if err == nil {
		if pinned, pErr := profile.LoadPinnedOrOfficial(stateDir); pErr == nil && pinned != nil {
			return pinned, nil
		}
	}
	return profile.Official(), nil
}

func buildRecordSource(prof *profile.Profile, manifestFile string) (resolver.RecordSource, error) {
	return buildRecordSourceWithStore(prof, manifestFile, nil)
}

func buildRecordSourceWithStore(prof *profile.Profile, manifestFile string, store *resolver.StateStore) (resolver.RecordSource, error) {
	if strings.TrimSpace(manifestFile) != "" {
		return resolver.LoadFixtureSourceFile(manifestFile, prof.Resolver.ManifestCID, prof.NetworkID)
	}
	if prof.Resolver.IPNSRoot != "" && len(prof.Resolver.Gateways) > 0 {
		return resolver.NewIPNSSource(resolver.IPNSOptions{
			IPNSRoot:        prof.Resolver.IPNSRoot,
			BootstrapCID:    prof.Resolver.ManifestCID,
			ExpectedNetwork: prof.NetworkID,
			Gateways:        prof.Resolver.Gateways,
			StateStore:      store,
		})
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

func buildVersionInfo() map[string]string {
	return map[string]string{
		"version":   Version,
		"commit":    Commit,
		"buildDate": BuildDate,
		"goVersion": runtime.Version(),
		"platform":  runtime.GOOS + "/" + runtime.GOARCH,
	}
}

func EnsurePKICA(stateDir, tld string) (string, error) {
	pkiDir := filepath.Join(stateDir, "pki")
	if _, err := pki.LoadOrCreateCAForTLD(pkiDir, tld); err != nil {
		return "", err
	}
	return filepath.Join(pkiDir, "ca.crt"), nil
}

var _ = sysinstall.DefaultLoopbackAliasIP
