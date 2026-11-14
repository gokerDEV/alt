package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"alt/pkg/config"
	"alt/pkg/daemon"
	"alt/pkg/names"
	"alt/pkg/profile"
	"alt/pkg/resolver"
	"alt/pkg/router"
	"alt/pkg/sysinstall"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

// splitPositionalAndFlags separates positional arguments from flags regardless of order
// (e.g., `alt dev goker.alt --port 3000` and `alt dev --port 3000 goker.alt` both work).
func splitPositionalAndFlags(args []string, boolFlags map[string]bool) (positional []string, flagArgs []string) {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if strings.HasPrefix(tok, "-") && tok != "-" {
			flagArgs = append(flagArgs, tok)
			name := strings.TrimLeft(tok, "-")
			if !strings.Contains(name, "=") && !boolFlags[name] && i+1 < len(args) {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		positional = append(positional, tok)
	}
	return positional, flagArgs
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func resolveCLIContext(profilePath, tldOverride, stateDirFlag string) (*profile.Profile, string, error) {
	prof, err := resolveNetworkProfileWithState(profilePath, tldOverride, stateDirFlag)
	if err != nil {
		return nil, "", err
	}
	baseStateDir, _, err := resolveRuntimeAndPKIDirs(stateDirFlag, prof.NetworkID)
	if err != nil {
		return nil, "", err
	}
	return prof, baseStateDir, nil
}

func tryConnectDaemon(ctx context.Context, stateDir string) (*daemon.IPCClient, *daemon.IPCStatusResponse) {
	client, err := daemon.NewIPCClient(stateDir)
	if err != nil {
		return nil, nil
	}
	stCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancel()
	st, err := client.Status(stCtx)
	if err != nil {
		return nil, nil
	}
	return client, st
}

// runSetup installs and activates macOS system integration (`/etc/resolver/<tld>`, `lo0` alias `127.0.0.2`,
// scoped PF port-443 translation anchor `com.apple/alt.<tld>`, Keychain Root CA trust, LaunchDaemon, and LaunchAgent).
func runSetup(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD (defaults to profile TLD or 'alt')")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	loopbackIP := flags.String("loopback-ip", sysinstall.DefaultLoopbackAliasIP, "dedicated lo0 alias IP (avoids colliding with Caddy/*:443 on 127.0.0.1)")
	httpsPort := flags.Int("https-port", sysinstall.DefaultDaemonHTTPSPort, "unprivileged daemon HTTPS listen port")
	dnsPort := flags.Int("dns-port", sysinstall.DefaultDaemonDNSPort, "unprivileged daemon UDP DNS listen port")
	targetUserFlag := flags.String("user", "", "target non-root macOS username (auto-detected under sudo/.pkg)")
	resolverDir := flags.String("resolver-dir", "", "override /etc/resolver directory (testing/sandbox)")
	pfAnchorsDir := flags.String("pf-anchors-dir", "", "override /etc/pf.anchors directory (testing/sandbox)")
	launchDaemonsDir := flags.String("launch-daemons-dir", "", "override /Library/LaunchDaemons directory (testing/sandbox)")
	launchAgentsDir := flags.String("launch-agents-dir", "", "override ~/Library/LaunchAgents directory (testing/sandbox)")
	skipOS := flags.Bool("skip-os-commands", false, "render files and receipt without invoking launchctl/pfctl/ifconfig/security")
	dryRun := flags.Bool("dry-run", false, "print planned system integration paths and rules without writing files")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{
		"skip-os-commands": true,
		"dry-run":          true,
		"json":             true,
	})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected positional argument %q", pos[0])
	}

	tu, err := sysinstall.ResolveTargetUser(*targetUserFlag)
	if err != nil {
		return err
	}

	// Resolve network profile and target user's state directory (never /var/root when invoked via sudo)
	prof, err := resolveNetworkProfileWithState(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}
	stateDir := strings.TrimSpace(*stateDirFlag)
	if stateDir == "" {
		stateDir = filepath.Join(tu.ConfigDir, "alt", "networks", prof.NetworkID)
	}
	stateDir, err = filepath.Abs(stateDir)
	if err != nil {
		return err
	}

	customSandboxDirs := *resolverDir != "" && *pfAnchorsDir != "" && *launchDaemonsDir != "" && *launchAgentsDir != ""
	if !*dryRun && !customSandboxDirs {
		if runtime.GOOS != "darwin" {
			return fmt.Errorf("automatic OS setup currently targets macOS (darwin); on %s use `alt run` or manual resolver setup", runtime.GOOS)
		}
		if os.Geteuid() != 0 {
			return errors.New("privileged system integration requires root to configure /etc/resolver, lo0 alias, pfctl, and System.keychain; re-run with: sudo alt setup")
		}
	}

	opts := sysinstall.Options{
		TLD:              prof.TLD,
		NetworkID:        prof.NetworkID,
		StateDir:         stateDir,
		LoopbackIP:       *loopbackIP,
		HTTPSPort:        *httpsPort,
		DNSPort:          *dnsPort,
		Uid:              tu.Uid,
		Gid:              tu.Gid,
		HomeDir:          tu.HomeDir,
		ResolverDir:      *resolverDir,
		PFAnchorsDir:     *pfAnchorsDir,
		LaunchDaemonsDir: *launchDaemonsDir,
		LaunchAgentsDir:  *launchAgentsDir,
	}

	plan, err := sysinstall.BuildPlan(opts)
	if err != nil {
		return err
	}

	if *dryRun {
		if *jsonOut {
			return printJSON(plan)
		}
		fmt.Printf("ALT System Setup Plan (dry-run — no files written)\n")
		fmt.Printf("  Network:       %s (.%s)\n", plan.Receipt.NetworkID, plan.Receipt.TLD)
		fmt.Printf("  Target User:   %s (uid=%d)\n", tu.Username, tu.Uid)
		fmt.Printf("  Loopback IP:   %s (dedicated lo0 alias; Caddy/*:443 untouched)\n", plan.Receipt.LoopbackIP)
		fmt.Printf("  Daemon Listen: https=%s:%d, dns=%s:%d\n", plan.Receipt.LoopbackIP, plan.Receipt.HTTPSPort, plan.Receipt.LoopbackIP, plan.Receipt.DNSPort)
		fmt.Printf("  Resolver File: %s\n", plan.Receipt.ResolverFilePath)
		fmt.Printf("  PF Anchor:     %s\n", plan.Receipt.PFAnchorFilePath)
		fmt.Printf("  LaunchDaemon:  %s\n", plan.Receipt.LaunchDaemonPlist)
		fmt.Printf("  LaunchAgent:   %s\n", plan.Receipt.LaunchAgentPlist)
		fmt.Printf("  Root CA:       %s\n", plan.Receipt.CACertPath)
		return nil
	}

	// Ensure constrained device-local Root CA exists before Keychain trust & LaunchAgent startup
	caCertPath, err := EnsurePKICA(stateDir, prof.TLD)
	if err != nil {
		return fmt.Errorf("initialize device-local Root CA: %w", err)
	}
	opts.CACertPath = caCertPath

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	applied, err := sysinstall.ApplyInstall(ctx, opts, sysinstall.DefaultRunner(), *skipOS || customSandboxDirs)
	if err != nil {
		return err
	}

	// Wait briefly for LaunchAgent daemon IPC health and live macOS mDNSResponder resolution if real OS commands ran
	daemonReady := false
	osDNSReady := false
	if !*skipOS && !customSandboxDirs && runtime.GOOS == "darwin" {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, st := tryConnectDaemon(ctx, stateDir); st != nil {
				daemonReady = true
				break
			}
			time.Sleep(150 * time.Millisecond)
		}
		if daemonReady {
			runner := sysinstall.DefaultRunner()
			probeHost := "register." + applied.Receipt.TLD
			dnsDeadline := time.Now().Add(4 * time.Second)
			reflushed := false
			for time.Now().Before(dnsDeadline) {
				lCtx, lCancel := context.WithTimeout(ctx, 800*time.Millisecond)
				addrs, lErr := net.DefaultResolver.LookupIPAddr(lCtx, probeHost)
				lCancel()
				if lErr == nil {
					for _, a := range addrs {
						if a.IP != nil && a.IP.String() == applied.Receipt.LoopbackIP {
							osDNSReady = true
							break
						}
					}
				}
				if osDNSReady {
					break
				}
				if !reflushed {
					reflushed = true
					_, _ = runner.Run(ctx, "/bin/sh", "-c", sysinstall.RenderScutilInstallShellCmd(applied.Receipt.TLD, applied.Receipt.LoopbackIP, applied.Receipt.DNSPort))
					_, _ = runner.Run(ctx, "/usr/bin/notifyutil", "-p", "com.apple.system.config.network_change")
					_, _ = runner.Run(ctx, "/usr/bin/dscacheutil", "-flushcache")
					_, _ = runner.Run(ctx, "/usr/bin/killall", "-HUP", "mDNSResponder")
				}
				time.Sleep(250 * time.Millisecond)
			}
		}
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"status":      "installed",
			"daemonReady": daemonReady,
			"osDNSReady":  osDNSReady,
			"receipt":     applied.Receipt,
		})
	}

	fmt.Printf("Installed ALT system integration for .%s (%s)\n", applied.Receipt.TLD, applied.Receipt.NetworkID)
	fmt.Printf("  Resolver:     %s + SCDynamicStore -> %s:%d\n", applied.Receipt.ResolverFilePath, applied.Receipt.LoopbackIP, applied.Receipt.DNSPort)
	fmt.Printf("  Port 443 PF:  %s:443 -> %s:%d (Caddy/*:443 untouched)\n", applied.Receipt.LoopbackIP, applied.Receipt.LoopbackIP, applied.Receipt.HTTPSPort)
	fmt.Printf("  Root CA:      %s (constrained to .%s)\n", applied.Receipt.CACertPath, applied.Receipt.TLD)
	fmt.Printf("  LaunchAgent:  %s\n", applied.Receipt.LaunchAgentPlist)
	if daemonReady {
		fmt.Printf("  Daemon:       running and healthy\n")
	}
	if osDNSReady {
		fmt.Printf("  macOS DNS:    verified (register.%s -> %s)\n", applied.Receipt.TLD, applied.Receipt.LoopbackIP)
	}
	fmt.Printf("Open https://register.%s (or your published https://<name>.%s) directly in your browser.\n", applied.Receipt.TLD, applied.Receipt.TLD)
	return nil
}

// runUninstall cleanly reverses `alt setup` without affecting Caddy or unrelated services.
func runUninstall(args []string) error {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	targetUserFlag := flags.String("user", "", "target non-root macOS username")
	resolverDir := flags.String("resolver-dir", "", "override /etc/resolver directory")
	pfAnchorsDir := flags.String("pf-anchors-dir", "", "override /etc/pf.anchors directory")
	launchDaemonsDir := flags.String("launch-daemons-dir", "", "override /Library/LaunchDaemons directory")
	launchAgentsDir := flags.String("launch-agents-dir", "", "override ~/Library/LaunchAgents directory")
	skipOS := flags.Bool("skip-os-commands", false, "remove files without invoking launchctl/pfctl/ifconfig/security")
	purgeState := flags.Bool("purge-state", false, "also delete cached resolver/daemon state and local CA (preserves owner keys unless --purge-all)")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{
		"skip-os-commands": true,
		"purge-state":      true,
		"json":             true,
	})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected positional argument %q", pos[0])
	}

	tu, err := sysinstall.ResolveTargetUser(*targetUserFlag)
	if err != nil {
		return err
	}

	prof, err := resolveNetworkProfileWithState(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}
	stateDir := strings.TrimSpace(*stateDirFlag)
	if stateDir == "" {
		stateDir = filepath.Join(tu.ConfigDir, "alt", "networks", prof.NetworkID)
	}
	stateDir, err = filepath.Abs(stateDir)
	if err != nil {
		return err
	}

	customSandboxDirs := *resolverDir != "" && *pfAnchorsDir != "" && *launchDaemonsDir != "" && *launchAgentsDir != ""
	if !customSandboxDirs && runtime.GOOS == "darwin" && os.Geteuid() != 0 {
		return errors.New("system uninstallation requires root to remove /etc/resolver, PF anchor, and LaunchDaemon; re-run with: sudo alt uninstall")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Ask running daemon to shut down cleanly if reachable
	if client, _ := tryConnectDaemon(ctx, stateDir); client != nil {
		_ = client.Shutdown(ctx)
		time.Sleep(100 * time.Millisecond)
	}

	opts := sysinstall.Options{
		TLD:              prof.TLD,
		NetworkID:        prof.NetworkID,
		StateDir:         stateDir,
		Uid:              tu.Uid,
		Gid:              tu.Gid,
		HomeDir:          tu.HomeDir,
		ResolverDir:      *resolverDir,
		PFAnchorsDir:     *pfAnchorsDir,
		LaunchDaemonsDir: *launchDaemonsDir,
		LaunchAgentsDir:  *launchAgentsDir,
	}

	removed, err := sysinstall.ApplyUninstall(ctx, opts, sysinstall.DefaultRunner(), *skipOS || customSandboxDirs)
	if err != nil {
		return err
	}

	if *purgeState {
		_ = os.Remove(filepath.Join(stateDir, "daemon-state.json"))
		_ = os.Remove(filepath.Join(stateDir, "resolver-state.json"))
		_ = os.Remove(filepath.Join(stateDir, "daemon.lock"))
		_ = os.RemoveAll(filepath.Join(stateDir, "pki"))
		_ = os.RemoveAll(filepath.Join(stateDir, "logs"))
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"status":      "uninstalled",
			"purgedState": *purgeState,
			"receipt":     removed.Receipt,
		})
	}

	fmt.Printf("Uninstalled ALT system integration for .%s\n", removed.Receipt.TLD)
	fmt.Printf("  Removed resolver, PF anchor, lo0 alias, CA trust, and launchd plists.\n")
	return nil
}

// runDaemonSubcommand manages the persistent background daemon directly (`start`, `stop`, `restart`, `reload`, `status`, `logs`).
func runDaemonSubcommand(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: alt daemon <start|stop|restart|reload|status|logs> [flags]")
	}
	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "status":
		return runStatus(subArgs)
	case "start":
		return runDaemonStart(subArgs)
	case "stop":
		return runDaemonStop(subArgs)
	case "restart":
		if err := runDaemonStop(subArgs); err != nil && !strings.Contains(err.Error(), "not running") {
			return err
		}
		return runDaemonStart(subArgs)
	case "reload":
		return runDaemonReload(subArgs)
	case "logs":
		return runDaemonLogs(subArgs)
	default:
		return fmt.Errorf("unknown daemon subcommand %q (expected start, stop, restart, reload, status, or logs)", sub)
	}
}

func runDaemonStart(args []string) error {
	flags := flag.NewFlagSet("daemon start", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listenAddr := flags.String("listen", "", "loopback HTTPS listen address (defaults to install receipt or 127.0.0.1:9443)")
	dnsListen := flags.String("dns-listen", "", "loopback UDP DNS listen address (defaults to install receipt or 127.0.0.1:15353)")
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	manifestFile := flags.String("manifest-file", "", "optional local manifest fixture file")
	gateways := flags.String("gateways", "", "comma-separated IPFS gateway URLs")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	prof, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if _, existing := tryConnectDaemon(ctx, stateDir); existing != nil {
		if *jsonOut {
			return printJSON(existing)
		}
		fmt.Printf("ALT daemon is already running (pid %d, https=%s, ipc=%s)\n",
			existing.PID, existing.HTTPSAddr, existing.SocketPath)
		return nil
	}

	effListen := strings.TrimSpace(*listenAddr)
	effDNS := strings.TrimSpace(*dnsListen)
	if receipt, rErr := sysinstall.LoadReceipt(stateDir); rErr == nil && receipt != nil {
		if effListen == "" && receipt.LoopbackIP != "" && receipt.HTTPSPort > 0 {
			effListen = net.JoinHostPort(receipt.LoopbackIP, strconv.Itoa(receipt.HTTPSPort))
		}
		if effDNS == "" && receipt.LoopbackIP != "" && receipt.DNSPort > 0 {
			effDNS = net.JoinHostPort(receipt.LoopbackIP, strconv.Itoa(receipt.DNSPort))
		}
	}
	if effListen == "" {
		effListen = fmt.Sprintf("127.0.0.1:%d", sysinstall.DefaultDaemonHTTPSPort)
	}
	if effDNS == "" {
		effDNS = fmt.Sprintf("127.0.0.1:%d", sysinstall.DefaultDaemonDNSPort)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}

	childArgs := []string{
		"run",
		"--daemon",
		"--listen", effListen,
		"--dns-listen", effDNS,
		"--state-dir", stateDir,
	}
	if strings.TrimSpace(*profileFlag) != "" {
		absProf, err := filepath.Abs(*profileFlag)
		if err != nil {
			return err
		}
		childArgs = append(childArgs, "--profile", absProf)
	} else if strings.TrimSpace(*tldFlag) != "" {
		childArgs = append(childArgs, "--tld", prof.TLD)
	}
	if strings.TrimSpace(*manifestFile) != "" {
		absMF, err := filepath.Abs(*manifestFile)
		if err != nil {
			return err
		}
		childArgs = append(childArgs, "--manifest-file", absMF)
	}
	if strings.TrimSpace(*gateways) != "" {
		childArgs = append(childArgs, "--gateways", *gateways)
	}

	logDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(logDir, "daemon.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	cmd := exec.Command(exe, childArgs...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start background daemon: %w", err)
	}
	_ = cmd.Process.Release()
	_ = logFile.Close()

	// Poll IPC socket until ready (up to 5 seconds)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, st := tryConnectDaemon(ctx, stateDir); st != nil {
			if *jsonOut {
				return printJSON(st)
			}
			fmt.Printf("Started ALT daemon (pid %d)\n", st.PID)
			fmt.Printf("  Network: %s (.%s)\n", st.NetworkID, st.TLD)
			fmt.Printf("  HTTPS:   %s\n", st.HTTPSAddr)
			if st.DNSAddr != "" {
				fmt.Printf("  DNS:     udp://%s\n", st.DNSAddr)
			}
			fmt.Printf("  IPC:     unix://%s\n", st.SocketPath)
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}

	tail, _ := readTailLines(filepath.Join(logDir, "daemon.log"), 15)
	if tail != "" {
		return fmt.Errorf("daemon did not become ready within 5s; recent log output:\n%s", tail)
	}
	return errors.New("daemon did not become ready within 5s")
}

func runDaemonStop(args []string) error {
	flags := flag.NewFlagSet("daemon stop", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	_, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, st := tryConnectDaemon(ctx, stateDir)
	if client == nil || st == nil {
		if *jsonOut {
			return printJSON(map[string]any{"status": "stopped", "wasRunning": false})
		}
		fmt.Println("ALT daemon is not running.")
		return nil
	}

	if err := client.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown daemon (pid %d): %w", st.PID, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, alive := tryConnectDaemon(context.Background(), stateDir); alive == nil {
			break
		}
		time.Sleep(60 * time.Millisecond)
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"status":     "stopped",
			"wasRunning": true,
			"stoppedPid": st.PID,
		})
	}
	fmt.Printf("Stopped ALT daemon (pid %d).\n", st.PID)
	return nil
}

func runDaemonReload(args []string) error {
	flags := flag.NewFlagSet("daemon reload", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	_, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, st := tryConnectDaemon(ctx, stateDir)
	if client == nil || st == nil {
		return errors.New("ALT daemon is not running; start it with `alt daemon start` or `sudo alt setup`")
	}
	resp, err := client.Reload(ctx)
	if err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp)
	}
	fmt.Printf("Reloaded %d tracked config file(s); %d local override site(s) active.\n", len(resp.ReloadedConfigs), resp.ActiveSites)
	return nil
}

func runDaemonLogs(args []string) error {
	flags := flag.NewFlagSet("daemon logs", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	lines := flags.Int("lines", 50, "number of recent log lines to print")
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")

	pos, flagArgs := splitPositionalAndFlags(args, nil)
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	_, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}
	logPath := filepath.Join(stateDir, "logs", "daemon.log")
	out, err := readTailLines(logPath, *lines)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("No daemon log file yet at %s\n", logPath)
			return nil
		}
		return err
	}
	if out == "" {
		fmt.Printf("Daemon log %s is empty.\n", logPath)
		return nil
	}
	fmt.Print(out)
	if !strings.HasSuffix(out, "\n") {
		fmt.Println()
	}
	return nil
}

func readTailLines(path string, maxLines int) (string, error) {
	if maxLines <= 0 {
		maxLines = 50
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	all := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(all) == 1 && all[0] == "" {
		return "", nil
	}
	if len(all) > maxLines {
		all = all[len(all)-maxLines:]
	}
	return strings.Join(all, "\n") + "\n", nil
}

// runDev configures and persists one or more local site overrides (`--port`, `--dir`, `--route`, or `--config`)
// and applies them live to the running daemon over Unix IPC.
func runDev(args []string) error {
	flags := flag.NewFlagSet("dev", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	portFlag := flags.Int("port", 0, "loopback HTTP port to proxy /* to (e.g. 3000)")
	dirFlag := flags.String("dir", "", "static directory to serve at /*")
	spaFlag := flags.Bool("spa", false, "enable SPA index.html fallback when --dir is used")
	var routeSpecs stringSliceFlag
	flags.Var(&routeSpecs, "route", "repeatable route rule <match>=<http://127.0.0.1:PORT | :PORT | dir:PATH>")
	configFlag := flags.String("config", "", "path to alt.yaml configuration file")
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	autoStart := flags.Bool("auto-start", false, "automatically start background daemon if not running")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{
		"spa":        true,
		"auto-start": true,
		"json":       true,
	})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 1 {
		return fmt.Errorf("unexpected argument %q (usage: alt dev [domain.alt] [--port N | --dir PATH | --route MATCH=TARGET | --config alt.yaml])", pos[1])
	}

	prof, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	var domainArg string
	if len(pos) == 1 {
		domainArg = pos[0]
	}

	cfgPath := strings.TrimSpace(*configFlag)
	// Default to ./alt.yaml if invoked as `alt dev` with no domain and no inline route flags
	if cfgPath == "" && domainArg == "" && *portFlag == 0 && strings.TrimSpace(*dirFlag) == "" && len(routeSpecs) == 0 {
		if _, stErr := os.Stat("alt.yaml"); stErr == nil {
			cfgPath = "alt.yaml"
		} else {
			return errors.New("usage: alt dev <domain.alt> --port <port> | --dir <dir> | --route <match=target> | alt dev --config alt.yaml")
		}
	}

	nowStr := time.Now().UTC().Format(time.RFC3339)
	var overrides []daemon.PersistedSiteOverride
	var trackedConfigAbs string

	if cfgPath != "" {
		if domainArg != "" || *portFlag != 0 || strings.TrimSpace(*dirFlag) != "" || len(routeSpecs) > 0 {
			return errors.New("--config cannot be combined with inline domain/--port/--dir/--route flags")
		}
		absCfg, err := filepath.Abs(cfgPath)
		if err != nil {
			return err
		}
		loaded, err := config.LoadFileForTLD(absCfg, prof.TLD)
		if err != nil {
			return err
		}
		baseDir := filepath.Dir(absCfg)
		domains := make([]string, 0, len(loaded.Sites))
		for d := range loaded.Sites {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		for _, d := range domains {
			entry := loaded.Sites[d]
			if _, err := router.NewSiteRouter(entry, baseDir); err != nil {
				return fmt.Errorf("invalid site %s in %s: %w", d, cfgPath, err)
			}
			overrides = append(overrides, daemon.PersistedSiteOverride{
				Domain:     d,
				SourceMode: "config",
				BaseDir:    baseDir,
				ConfigFile: absCfg,
				Entry:      entry,
				UpdatedAt:  nowStr,
			})
		}
		trackedConfigAbs = absCfg
	} else {
		if domainArg == "" {
			return errors.New("domain argument is required unless --config is provided (e.g. alt dev app.alt --port 3000)")
		}
		normDomain, err := names.NormalizeDomain(domainArg, prof.TLD)
		if err != nil {
			return err
		}

		modesSet := 0
		if *portFlag != 0 {
			modesSet++
		}
		if strings.TrimSpace(*dirFlag) != "" {
			modesSet++
		}
		if len(routeSpecs) > 0 {
			modesSet++
		}
		if modesSet == 0 {
			return fmt.Errorf("specify one of --port, --dir, or --route for %s", normDomain)
		}
		if modesSet > 1 {
			return errors.New("--port, --dir, and --route are mutually exclusive; use multiple --route flags to combine routes")
		}

		cwd, err := os.Getwd()
		if err != nil {
			cwd = "."
		}

		var entry config.SiteEntry
		var sourceMode string
		baseDir := cwd

		switch {
		case *portFlag != 0:
			if *portFlag < 1 || *portFlag > 65535 {
				return errors.New("--port must be between 1 and 65535")
			}
			sourceMode = "port"
			entry = config.SiteEntry{
				Routes: []config.RouteEntry{
					{
						Match:    "/*",
						Upstream: "http://127.0.0.1:" + strconv.Itoa(*portFlag),
					},
				},
			}
		case strings.TrimSpace(*dirFlag) != "":
			absDir, err := filepath.Abs(strings.TrimSpace(*dirFlag))
			if err != nil {
				return err
			}
			st, err := os.Stat(absDir)
			if err != nil || !st.IsDir() {
				return fmt.Errorf("--dir %q does not exist or is not a directory", *dirFlag)
			}
			sourceMode = "dir"
			baseDir = absDir
			entry = config.SiteEntry{
				Routes: []config.RouteEntry{
					{
						Match: "/*",
						Static: &config.StaticEntry{
							Dir:         absDir,
							SPAFallback: *spaFlag,
						},
					},
				},
			}
		case len(routeSpecs) > 0:
			sourceMode = "routes"
			parsedRoutes, err := parseCLIRouteSpecs(routeSpecs, cwd)
			if err != nil {
				return err
			}
			entry = config.SiteEntry{Routes: parsedRoutes}
		}

		if err := entry.ValidateRoutes(); err != nil {
			return err
		}
		if _, err := router.NewSiteRouter(entry, baseDir); err != nil {
			return err
		}

		overrides = append(overrides, daemon.PersistedSiteOverride{
			Domain:     normDomain,
			SourceMode: sourceMode,
			BaseDir:    baseDir,
			Entry:      entry,
			UpdatedAt:  nowStr,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, st := tryConnectDaemon(ctx, stateDir)
	if client == nil && *autoStart {
		var startArgs []string
		if *profileFlag != "" {
			startArgs = append(startArgs, "--profile", *profileFlag)
		} else if *tldFlag != "" {
			startArgs = append(startArgs, "--tld", prof.TLD)
		}
		startArgs = append(startArgs, "--state-dir", stateDir)
		if err := runDaemonStart(startArgs); err != nil {
			return err
		}
		client, st = tryConnectDaemon(ctx, stateDir)
	}

	if client != nil && st != nil {
		resp, err := client.DevUpsert(ctx, daemon.IPCDevUpsertRequest{
			Overrides:  overrides,
			ConfigFile: trackedConfigAbs,
		})
		if err != nil {
			return err
		}
		if *jsonOut {
			return printJSON(map[string]any{
				"daemonStatus": "running",
				"httpsAddr":    resp.HTTPSAddr,
				"activated":    resp.Activated,
			})
		}
		for _, ov := range resp.Activated {
			fmt.Printf("Active local override: https://%s%s (%s)\n",
				ov.Domain, displayPortFromReceiptOrAddr(stateDir, resp.HTTPSAddr), summarizeRoutes(ov.Entry))
		}
		return nil
	}

	// Daemon is not running: persist into DaemonStateStore so the next `alt daemon start` or `alt run` serves it immediately
	store, err := daemon.OpenDaemonStateStore(filepath.Join(stateDir, "daemon-state.json"), prof.NetworkID, prof.TLD)
	if err != nil {
		return err
	}
	if err := store.Upsert(overrides, trackedConfigAbs); err != nil {
		return err
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"daemonStatus": "stopped",
			"persisted":    overrides,
			"stateFile":    store.Path(),
		})
	}
	for _, ov := range overrides {
		fmt.Printf("Saved local override: %s (%s)\n", ov.Domain, summarizeRoutes(ov.Entry))
	}
	fmt.Println("Note: ALT daemon is not currently running. Start it with `alt daemon start` (or `sudo alt setup` for browser port 443).")
	return nil
}

func parseCLIRouteSpecs(specs []string, cwd string) ([]config.RouteEntry, error) {
	routes := make([]config.RouteEntry, 0, len(specs))
	for _, raw := range specs {
		eq := strings.IndexByte(raw, '=')
		if eq <= 0 || eq == len(raw)-1 {
			return nil, fmt.Errorf("invalid --route %q: expected <match>=<target> (e.g. /api/*=http://127.0.0.1:8080 or /*=3000)", raw)
		}
		match := strings.TrimSpace(raw[:eq])
		target := strings.TrimSpace(raw[eq+1:])

		if strings.HasPrefix(target, "dir:") {
			dirVal := strings.TrimSpace(strings.TrimPrefix(target, "dir:"))
			absDir, err := filepath.Abs(filepath.Join(cwd, dirVal))
			if strings.HasPrefix(dirVal, "/") {
				absDir, err = filepath.Abs(dirVal)
			}
			if err != nil {
				return nil, err
			}
			routes = append(routes, config.RouteEntry{
				Match:  match,
				Static: &config.StaticEntry{Dir: absDir},
			})
			continue
		}

		// Support shorthand `:3000` or `3000`
		portStr := strings.TrimPrefix(target, ":")
		if p, err := strconv.Atoi(portStr); err == nil && p >= 1 && p <= 65535 {
			target = "http://127.0.0.1:" + strconv.Itoa(p)
		}

		routes = append(routes, config.RouteEntry{
			Match:    match,
			Upstream: target,
		})
	}
	return routes, nil
}

func summarizeRoutes(entry config.SiteEntry) string {
	parts := make([]string, 0, len(entry.Routes))
	for _, r := range entry.Routes {
		if r.Static != nil {
			mode := "dir:" + r.Static.Dir
			if r.Static.SPAFallback {
				mode += " [spa]"
			}
			parts = append(parts, fmt.Sprintf("%s -> %s", r.Match, mode))
		} else {
			parts = append(parts, fmt.Sprintf("%s -> %s", r.Match, r.Upstream))
		}
	}
	return strings.Join(parts, ", ")
}

func displayPortFromReceiptOrAddr(stateDir, httpsAddr string) string {
	if receipt, err := sysinstall.LoadReceipt(stateDir); err == nil && receipt != nil {
		expected := net.JoinHostPort(receipt.LoopbackIP, strconv.Itoa(receipt.HTTPSPort))
		if httpsAddr == expected {
			return ""
		}
	}
	return displayPort(httpsAddr)
}

// runList lists active local overrides from the running daemon (or persisted overrides when stopped).
func runList(args []string) error {
	flags := flag.NewFlagSet("list", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	prof, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var sites []daemon.PersistedSiteOverride
	daemonState := "stopped"
	var httpsAddr string

	if client, st := tryConnectDaemon(ctx, stateDir); client != nil && st != nil {
		daemonState = "running"
		httpsAddr = st.HTTPSAddr
		if listResp, lErr := client.ListSites(ctx); lErr == nil {
			sites = listResp.Sites
		} else {
			sites = st.Sites
		}
	} else if store, sErr := daemon.OpenDaemonStateStore(filepath.Join(stateDir, "daemon-state.json"), prof.NetworkID, prof.TLD); sErr == nil {
		sites = store.List()
	}

	if sites == nil {
		sites = []daemon.PersistedSiteOverride{}
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"networkId":    prof.NetworkID,
			"tld":          prof.TLD,
			"daemonStatus": daemonState,
			"httpsAddr":    httpsAddr,
			"sites":        sites,
		})
	}

	if len(sites) == 0 {
		fmt.Printf("No local overrides configured for %s (.%s) [daemon: %s].\n", prof.NetworkID, prof.TLD, daemonState)
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tSOURCE\tSTATUS\tROUTES")
	statusLabel := "active"
	if daemonState != "running" {
		statusLabel = "persisted (daemon stopped)"
	}
	for _, s := range sites {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Domain, s.SourceMode, statusLabel, summarizeRoutes(s.Entry))
	}
	return tw.Flush()
}

// runHalt removes a local override (or all overrides with `--all`), restoring signed network resolution.
func runHalt(args []string) error {
	flags := flag.NewFlagSet("halt", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	allFlag := flags.Bool("all", false, "remove all local overrides")
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{
		"all":  true,
		"json": true,
	})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}

	if *allFlag && len(pos) > 0 {
		return errors.New("cannot specify both a domain name and --all")
	}
	if !*allFlag && len(pos) != 1 {
		return errors.New("usage: alt halt <domain.alt> | alt halt --all")
	}

	prof, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	var normDomain string
	if !*allFlag {
		normDomain, err = names.NormalizeDomain(pos[0], prof.TLD)
		if err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if client, st := tryConnectDaemon(ctx, stateDir); client != nil && st != nil {
		resp, err := client.Halt(ctx, daemon.IPCHaltRequest{
			Domain: normDomain,
			All:    *allFlag,
		})
		if err != nil {
			return err
		}
		if *jsonOut {
			return printJSON(resp)
		}
		if *allFlag {
			fmt.Printf("Removed %d local override(s) from running daemon.\n", resp.Removed)
			return nil
		}
		if resp.Removed == 0 {
			fmt.Printf("No active local override found for %s.\n", normDomain)
			return nil
		}
		fmt.Printf("Halted local override for %s (signed network resolution restored).\n", normDomain)
		return nil
	}

	store, err := daemon.OpenDaemonStateStore(filepath.Join(stateDir, "daemon-state.json"), prof.NetworkID, prof.TLD)
	if err != nil {
		return err
	}
	if *allFlag {
		existing := store.List()
		domains := make([]string, 0, len(existing))
		for _, s := range existing {
			domains = append(domains, s.Domain)
		}
		if err := store.Clear(); err != nil {
			return err
		}
		if *jsonOut {
			return printJSON(daemon.IPCHaltResponse{Removed: len(domains), Domains: domains})
		}
		fmt.Printf("Removed %d persisted local override(s).\n", len(domains))
		return nil
	}

	removed, err := store.Remove(normDomain)
	if err != nil {
		return err
	}
	if *jsonOut {
		var domains []string
		n := 0
		if removed {
			n = 1
			domains = []string{normDomain}
		}
		return printJSON(daemon.IPCHaltResponse{Removed: n, Domains: domains})
	}
	if !removed {
		fmt.Printf("No local override found for %s.\n", normDomain)
		return nil
	}
	fmt.Printf("Removed persisted local override for %s.\n", normDomain)
	return nil
}

// runStatus reports live daemon, IPC, OS integration receipt, CA, local override, and persistent resolver cache status.
func runStatus(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	prof, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, live := tryConnectDaemon(ctx, stateDir)
	receipt, _ := sysinstall.LoadReceipt(stateDir)

	if live != nil {
		if *jsonOut {
			return printJSON(map[string]any{
				"daemon":          live,
				"systemInstalled": receipt != nil,
				"installReceipt":  receipt,
			})
		}
		fmt.Printf("ALT Status: running (pid %d, uptime %ds, version %s)\n", live.PID, live.UptimeSeconds, live.Version)
		fmt.Printf("  Network:        %s (.%s)\n", live.NetworkID, live.TLD)
		fmt.Printf("  HTTPS Listen:   %s\n", live.HTTPSAddr)
		if live.DNSAddr != "" {
			fmt.Printf("  DNS Stub:       udp://%s\n", live.DNSAddr)
		}
		fmt.Printf("  IPC Socket:     unix://%s\n", live.SocketPath)
		fmt.Printf("  Root CA:        %s\n", live.CACertPath)
		fmt.Printf("  Local Sites:    %d active override(s)\n", len(live.Sites))
		fmt.Printf("  Resolver Cache: %d verified domain(s) (persistent=%v)\n",
			live.Resolver.CachedDomains, live.Resolver.PersistentBacked)
		if live.Resolver.IPNSHasSequence {
			fmt.Printf("  IPNS Watermark: seq=%d -> %s\n", live.Resolver.IPNSSequence, live.Resolver.IPNSTargetCID)
		} else if live.Resolver.IPNSRoot != "" {
			fmt.Printf("  IPNS Root:      %s\n", live.Resolver.IPNSRoot)
		}
		if receipt != nil {
			fmt.Printf("  macOS Setup:    installed (lo0 %s:443 -> %d, %s)\n",
				receipt.LoopbackIP, receipt.HTTPSPort, receipt.ResolverFilePath)
		} else {
			fmt.Printf("  macOS Setup:    not installed (run `sudo alt setup` for browser port 443)\n")
		}
		return nil
	}

	// Offline inspection of persisted stores when daemon is stopped
	var persistedSites []daemon.PersistedSiteOverride
	if ds, dsErr := daemon.OpenDaemonStateStore(filepath.Join(stateDir, "daemon-state.json"), prof.NetworkID, prof.TLD); dsErr == nil {
		persistedSites = ds.List()
	}
	var cachedCount int
	var ipnsState *resolver.PersistedIPNSState
	resStatePath := filepath.Join(stateDir, "resolver-state.json")
	if rs, rsErr := resolver.OpenStateStore(resStatePath, prof.NetworkID); rsErr == nil {
		cachedCount = len(rs.SnapshotDomains())
		ipnsState = rs.SnapshotIPNS()
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"daemon": map[string]any{
				"status":        "stopped",
				"networkId":     prof.NetworkID,
				"tld":           prof.TLD,
				"stateDir":      stateDir,
				"sites":         persistedSites,
				"cachedDomains": cachedCount,
				"ipns":          ipnsState,
			},
			"systemInstalled": receipt != nil,
			"installReceipt":  receipt,
		})
	}

	fmt.Printf("ALT Status: stopped\n")
	fmt.Printf("  Network:        %s (.%s)\n", prof.NetworkID, prof.TLD)
	fmt.Printf("  State Dir:      %s\n", stateDir)
	fmt.Printf("  Persisted Dev:  %d site override(s)\n", len(persistedSites))
	fmt.Printf("  Resolver State: %d persisted verified domain(s)\n", cachedCount)
	if ipnsState != nil {
		fmt.Printf("  IPNS Watermark: seq=%d -> %s\n", ipnsState.HighestSequence, ipnsState.TargetCID)
	}
	if receipt != nil {
		fmt.Printf("  macOS Setup:    installed (%s) — start daemon with `alt daemon start`\n", receipt.ResolverFilePath)
	} else {
		fmt.Printf("  macOS Setup:    not installed (run `sudo alt setup`)\n")
	}
	return nil
}

// runDoctor executes live verification checks across IPC, DNS stub, `/etc/resolver`, X.509 CA constraints,
// `lo0` loopback alias coexistence, and PF port-443 translation.
func runDoctor(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	prof, err := resolveNetworkProfileWithState(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}
	stateDir, caDir, err := resolveRuntimeAndPKIDirs(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, live := tryConnectDaemon(ctx, stateDir)
	receipt, _ := sysinstall.LoadReceipt(stateDir)

	in := sysinstall.DoctorInput{
		NetworkID:  prof.NetworkID,
		TLD:        prof.TLD,
		StateDir:   stateDir,
		CACertPath: filepath.Join(caDir, "ca.crt"),
		LoopbackIP: sysinstall.DefaultLoopbackAliasIP,
	}
	if receipt != nil {
		if receipt.CACertPath != "" {
			in.CACertPath = receipt.CACertPath
		}
		in.ResolverFilePath = receipt.ResolverFilePath
		in.PFAnchorFilePath = receipt.PFAnchorFilePath
		if receipt.LoopbackIP != "" {
			in.LoopbackIP = receipt.LoopbackIP
		}
	}
	if live != nil {
		in.DaemonRunning = true
		in.DaemonPID = live.PID
		in.DaemonHTTPSAddr = live.HTTPSAddr
		in.DaemonDNSAddr = live.DNSAddr
		if live.CACertPath != "" {
			in.CACertPath = live.CACertPath
		}
		if live.LoopbackIP != "" && receipt == nil {
			in.LoopbackIP = live.LoopbackIP
		}
	}

	report := sysinstall.RunDoctorChecks(ctx, in)
	if *jsonOut {
		if err := printJSON(report); err != nil {
			return err
		}
		if !report.Healthy {
			return errors.New("doctor detected failing health checks")
		}
		return nil
	}

	fmt.Printf("ALT Doctor — %s (.%s)\n\n", report.NetworkID, report.TLD)
	for _, c := range report.Checks {
		badge := "[OK]  "
		switch c.Status {
		case "warn":
			badge = "[WARN]"
		case "fail":
			badge = "[FAIL]"
		}
		fmt.Printf("  %s %s: %s\n", badge, c.Name, c.Summary)
		if c.Remediation != "" && c.Status != "ok" {
			fmt.Printf("         -> %s\n", c.Remediation)
		}
	}
	fmt.Println()
	if !report.Healthy {
		return errors.New("doctor detected failing health checks")
	}
	fmt.Println("All required ALT checks passed.")
	return nil
}

// runProfileSubcommand inspects or applies authority-signed network profile / trust-root updates.
func runProfileSubcommand(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: alt profile <show|update> [arguments]")
	}
	switch args[0] {
	case "show":
		return runProfileShow(args[1:])
	case "update":
		return runProfileUpdate(args[1:])
	default:
		return fmt.Errorf("unknown profile subcommand %q (expected 'show' or 'update')", args[0])
	}
}

func runProfileShow(args []string) error {
	flags := flag.NewFlagSet("profile show", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	tldFlag := flags.String("tld", "", "private namespace TLD")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}
	if len(pos) > 0 {
		return fmt.Errorf("unexpected argument %q", pos[0])
	}

	prof, stateDir, err := resolveCLIContext(*profileFlag, *tldFlag, *stateDirFlag)
	if err != nil {
		return err
	}
	pinnedPath := profile.PinnedProfilePath(stateDir)
	_, pinnedErr := os.Stat(pinnedPath)
	isPinned := pinnedErr == nil
	meta, _ := profile.LoadBundleMeta(stateDir)

	if *jsonOut {
		return printJSON(map[string]any{
			"profile":    prof,
			"pinned":     isPinned,
			"pinnedPath": pinnedPath,
			"bundleMeta": meta,
		})
	}

	sourceDesc := "embedded official trust store"
	if strings.TrimSpace(*profileFlag) != "" {
		sourceDesc = *profileFlag
	} else if isPinned {
		sourceDesc = pinnedPath
	}
	fmt.Printf("Network Profile: %s (.%s)\n", prof.NetworkID, prof.TLD)
	fmt.Printf("  Source:        %s\n", sourceDesc)
	if meta != nil {
		fmt.Printf("  Bundle Seq:    %d (signed by %s at %s)\n", meta.Sequence, meta.SignerKeyID, meta.UpdatedAt)
	}
	fmt.Printf("  Authority Keys (%d):\n", len(prof.RegistryKeys))
	for _, k := range prof.RegistryKeys {
		fmt.Printf("    - %s: %s\n", k.ID, k.PublicKey)
	}
	if prof.Resolver.IPNSRoot != "" {
		fmt.Printf("  IPNS Root:     %s\n", prof.Resolver.IPNSRoot)
	}
	if prof.Resolver.ManifestCID != "" {
		fmt.Printf("  Bootstrap CID: %s\n", prof.Resolver.ManifestCID)
	}
	if len(prof.Resolver.Gateways) > 0 {
		fmt.Printf("  Gateways:      %s\n", strings.Join(prof.Resolver.Gateways, ", "))
	}
	return nil
}

func runProfileUpdate(args []string) error {
	flags := flag.NewFlagSet("profile update", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	urlFlag := flags.String("url", "", "HTTPS URL serving a signed alt.profile-bundle.v1 JSON document")
	profileFlag := flags.String("profile", os.Getenv("ALT_PROFILE"), "current trusted network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "state directory override")
	jsonOut := flags.Bool("json", false, "emit structured JSON output")

	pos, flagArgs := splitPositionalAndFlags(args, map[string]bool{"json": true})
	if err := flags.Parse(flagArgs); err != nil {
		return err
	}

	var rawBundle []byte
	var err error
	if strings.TrimSpace(*urlFlag) != "" {
		if len(pos) > 0 {
			return errors.New("cannot specify both a bundle file path and --url")
		}
		u := strings.TrimSpace(*urlFlag)
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://127.0.0.1:") && !strings.HasPrefix(u, "http://localhost:") {
			return errors.New("profile bundle --url must use https:// (or loopback http:// for local testing)")
		}
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Get(u)
		if err != nil {
			return fmt.Errorf("fetch profile bundle: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("profile bundle endpoint returned HTTP %d", resp.StatusCode)
		}
		rawBundle, err = io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		if err != nil {
			return err
		}
	} else {
		if len(pos) != 1 {
			return errors.New("usage: alt profile update <bundle.json | --url https://...>")
		}
		rawBundle, err = os.ReadFile(pos[0])
		if err != nil {
			return err
		}
	}

	bundle, err := profile.DecodeSignedBundleStrict(rawBundle)
	if err != nil {
		return err
	}

	currentProf, stateDir, err := resolveCLIContext(*profileFlag, "", *stateDirFlag)
	if err != nil {
		return err
	}

	updatedProf, err := profile.ApplySignedBundleToStateDir(stateDir, currentProf, bundle, time.Now().UTC())
	if err != nil {
		return err
	}

	if *jsonOut {
		return printJSON(map[string]any{
			"status":     "updated",
			"networkId":  updatedProf.NetworkID,
			"sequence":   bundle.Sequence,
			"pinnedPath": profile.PinnedProfilePath(stateDir),
			"profile":    updatedProf,
		})
	}

	fmt.Printf("Verified and applied signed profile bundle (sequence %d, signer %s) for %s.\n",
		bundle.Sequence, bundle.SignerKeyID, updatedProf.NetworkID)
	fmt.Printf("Pinned to %s (restart daemon with `alt daemon restart` to apply trust-root changes to running proxy).\n",
		profile.PinnedProfilePath(stateDir))
	return nil
}

// runVersion prints build metadata (`alt version [--json]`).
func runVersion(args []string) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	jsonOut := flags.Bool("json", false, "emit structured JSON output")
	if err := flags.Parse(args); err != nil {
		return err
	}
	info := buildVersionInfo()
	if *jsonOut {
		return printJSON(info)
	}
	fmt.Printf("alt version %s (commit: %s, built: %s, %s, %s)\n",
		info["version"], info["commit"], info["buildDate"], info["platform"], info["goVersion"])
	return nil
}

// runCompletion outputs shell completion scripts for zsh, bash, or fish.
func runCompletion(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: alt completion <zsh|bash|fish>")
	}
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "zsh":
		fmt.Print(zshCompletionScript)
	case "bash":
		fmt.Print(bashCompletionScript)
	case "fish":
		fmt.Print(fishCompletionScript)
	default:
		return fmt.Errorf("unsupported shell %q (expected zsh, bash, or fish)", args[0])
	}
	return nil
}

const zshCompletionScript = `#compdef alt

_alt() {
  local -a commands
  commands=(
    'setup:Install macOS .alt resolver, CA trust, lo0 alias, PF port 443 rule, and LaunchAgent'
    'uninstall:Cleanly remove macOS .alt resolver, PF rule, lo0 alias, CA trust, and LaunchAgent'
    'daemon:Manage background ALT daemon (start, stop, restart, reload, status, logs)'
    'login:Authenticate account via GitHub Device Flow'
    'logout:Revoke CLI session and delete local token'
    'account:Display authenticated GitHub account and .alt domain'
    'dev:Configure local override (--port, --dir, --route, --config)'
    'run:Run foreground loopback HTTPS proxy and DNS stub'
    'publish:Sign and publish an HTTPS target record'
    'config:Validate alt.yaml configuration'
    'profile:Inspect or update signed network profile bundle'
    'register:Bind local Ed25519 owner key and register a .alt domain'
    'list:List active and persisted local overrides'
    'halt:Remove local override for a domain or --all'
    'status:Show live daemon, resolver cache, and OS setup status'
    'doctor:Run live DNS, CA, resolver, and port 443 coexistence checks'
    'version:Print version and build metadata'
    'completion:Generate shell completion script'
  )

  if (( CURRENT == 2 )); then
    _describe -t commands 'alt command' commands
    return
  fi

  case "${words[2]}" in
    daemon)
      _values 'daemon subcommand' start stop restart reload status logs
      ;;
    profile)
      _values 'profile subcommand' show update
      ;;
    config)
      _values 'config subcommand' validate
      ;;
    login)
      _values 'login provider' github
      ;;
    completion)
      _values 'shell' zsh bash fish
      ;;
    *)
      _files
      ;;
  esac
}

compdef _alt alt
`

const bashCompletionScript = `# bash completion for alt
_alt_completions() {
  local cur prev cmds
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmds="setup uninstall daemon login logout account dev run publish config profile register list halt status doctor version completion help"

  if [[ ${COMP_CWORD} -eq 1 ]]; then
    COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
    return 0
  fi

  case "${COMP_WORDS[1]}" in
    daemon)
      COMPREPLY=( $(compgen -W "start stop restart reload status logs" -- "${cur}") )
      ;;
    profile)
      COMPREPLY=( $(compgen -W "show update" -- "${cur}") )
      ;;
    config)
      COMPREPLY=( $(compgen -W "validate" -- "${cur}") )
      ;;
    login)
      COMPREPLY=( $(compgen -W "github" -- "${cur}") )
      ;;
    completion)
      COMPREPLY=( $(compgen -W "zsh bash fish" -- "${cur}") )
      ;;
  esac
}
complete -F _alt_completions alt
`

const fishCompletionScript = `# fish completion for alt
set -l alt_commands setup uninstall daemon login logout account dev run publish config profile register list halt status doctor version completion help
complete -c alt -f -n "not __fish_seen_subcommand_from $alt_commands" -a "$alt_commands"
complete -c alt -f -n "__fish_seen_subcommand_from daemon" -a "start stop restart reload status logs"
complete -c alt -f -n "__fish_seen_subcommand_from profile" -a "show update"
complete -c alt -f -n "__fish_seen_subcommand_from config" -a "validate"
complete -c alt -f -n "__fish_seen_subcommand_from login" -a "github"
complete -c alt -f -n "__fish_seen_subcommand_from completion" -a "zsh bash fish"
`
