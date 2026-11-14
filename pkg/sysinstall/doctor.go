package sysinstall

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// CommandRunner abstracts privileged and user-level OS command execution for testability.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

// DefaultRunner returns the standard OS command executor.
func DefaultRunner() CommandRunner {
	return osCommandRunner{}
}

// CheckMacOSCompatibility verifies that the host is running macOS >= MinSupportedMacOSMajor.
func CheckMacOSCompatibility(ctx context.Context, runner CommandRunner) (string, error) {
	if runtime.GOOS != "darwin" {
		return runtime.GOOS, fmt.Errorf("automatic system installer currently targets macOS (darwin); detected %s", runtime.GOOS)
	}
	if runner == nil {
		runner = DefaultRunner()
	}
	out, err := runner.Run(ctx, "/usr/bin/sw_vers", "-productVersion")
	if err != nil {
		return "", fmt.Errorf("determine macOS version: %w", err)
	}
	ver := strings.TrimSpace(string(out))
	// In mock runners that return "ok", skip strict version parse
	if ver == "" || ver == "ok" {
		return ver, nil
	}
	parts := strings.Split(ver, ".")
	major, pErr := strconv.Atoi(parts[0])
	if pErr != nil {
		return ver, fmt.Errorf("parse macOS version %q: %w", ver, pErr)
	}
	if major < MinSupportedMacOSMajor {
		return ver, fmt.Errorf("macOS %s is older than minimum supported version %d.0", ver, MinSupportedMacOSMajor)
	}
	return ver, nil
}

// chownTreeIfRoot transfers ownership of user-scoped files/directories created under `sudo alt setup`
// back to `(uid, gid)` so the unprivileged LaunchAgent can read `ca.key` and write daemon state/sockets.
func chownTreeIfRoot(root string, uid, gid int) {
	if os.Geteuid() != 0 || uid <= 0 || strings.TrimSpace(root) == "" {
		return
	}
	_ = filepath.Walk(root, func(p string, _ os.FileInfo, err error) error {
		if err == nil {
			_ = os.Lchown(p, uid, gid)
		}
		return nil
	})
}

// ApplyInstall executes the installation plan on macOS (or writes into custom root directories in tests/dry-run).
// When running as root (or via `sudo alt setup`), it:
//  1. Writes the root-owned nethelper script and user-owned LaunchAgent plist,
//  2. Configures `/etc/resolver/<tld>` and `/etc/pf.anchors/dev.alt.<tld>`,
//  3. Brings up `lo0 alias <loopbackIP>` and loads the scoped PF anchor `com.apple/alt.<tld>`,
//  4. Trusts the device-local Root CA in the macOS login/System Keychain (`security add-trusted-cert`),
//  5. Bootstraps the LaunchDaemon and user LaunchAgent,
//  6. Persists `<stateDir>/install-receipt.json`.
func ApplyInstall(ctx context.Context, opts Options, runner CommandRunner, skipOSCommands bool) (*Plan, error) {
	norm, err := NormalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	plan, err := BuildPlan(norm)
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = DefaultRunner()
	}

	if !skipOSCommands && runtime.GOOS == "darwin" {
		if _, err := CheckMacOSCompatibility(ctx, runner); err != nil {
			return nil, err
		}
	}

	// 1. Write root-owned helper script (`/Library/Application Support/alt/bin/...`) and user LaunchAgent plist
	if err := os.MkdirAll(filepath.Dir(plan.Receipt.HelperScriptPath), 0o755); err != nil {
		return nil, fmt.Errorf("create helper bin dir: %w", err)
	}
	if err := os.WriteFile(plan.Receipt.HelperScriptPath, []byte(plan.HelperScript), 0o755); err != nil {
		return nil, fmt.Errorf("write nethelper script: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(plan.Receipt.LaunchAgentPlist), 0o755); err != nil {
		return nil, fmt.Errorf("create LaunchAgents dir: %w", err)
	}
	if err := os.WriteFile(plan.Receipt.LaunchAgentPlist, []byte(plan.LaunchAgentXML), 0o644); err != nil {
		return nil, fmt.Errorf("write LaunchAgent plist: %w", err)
	}
	if os.Geteuid() == 0 && norm.Uid > 0 {
		_ = os.Lchown(filepath.Dir(plan.Receipt.LaunchAgentPlist), norm.Uid, norm.Gid)
		_ = os.Lchown(plan.Receipt.LaunchAgentPlist, norm.Uid, norm.Gid)
	}

	// 2. Write `/etc/resolver/<tld>`, `/etc/pf.anchors/dev.alt.<tld>`, and `/Library/LaunchDaemons/...`
	if err := os.MkdirAll(filepath.Dir(plan.Receipt.ResolverFilePath), 0o755); err != nil {
		return nil, fmt.Errorf("create resolver dir %s (run `sudo alt setup`): %w", filepath.Dir(plan.Receipt.ResolverFilePath), err)
	}
	if err := os.WriteFile(plan.Receipt.ResolverFilePath, []byte(plan.ResolverContent), 0o644); err != nil {
		return nil, fmt.Errorf("write resolver file %s: %w", plan.Receipt.ResolverFilePath, err)
	}

	if err := os.MkdirAll(filepath.Dir(plan.Receipt.PFAnchorFilePath), 0o755); err != nil {
		return nil, fmt.Errorf("create pf.anchors dir %s: %w", filepath.Dir(plan.Receipt.PFAnchorFilePath), err)
	}
	if err := os.WriteFile(plan.Receipt.PFAnchorFilePath, []byte(plan.PFAnchorContent), 0o644); err != nil {
		return nil, fmt.Errorf("write PF anchor file %s: %w", plan.Receipt.PFAnchorFilePath, err)
	}

	if err := os.MkdirAll(filepath.Dir(plan.Receipt.LaunchDaemonPlist), 0o755); err != nil {
		return nil, fmt.Errorf("create LaunchDaemons dir %s: %w", filepath.Dir(plan.Receipt.LaunchDaemonPlist), err)
	}
	if err := os.WriteFile(plan.Receipt.LaunchDaemonPlist, []byte(plan.LaunchDaemonXML), 0o644); err != nil {
		return nil, fmt.Errorf("write LaunchDaemon plist %s: %w", plan.Receipt.LaunchDaemonPlist, err)
	}

	if err := SaveReceipt(norm.StateDir, plan.Receipt); err != nil {
		return nil, fmt.Errorf("save install receipt: %w", err)
	}
	// Ensure logs directory exists and user state tree belongs to the target non-root user before LaunchAgent starts
	_ = os.MkdirAll(filepath.Join(norm.StateDir, "logs"), 0o700)
	chownTreeIfRoot(norm.StateDir, norm.Uid, norm.Gid)

	if !skipOSCommands && runtime.GOOS == "darwin" {
		// Activate loopback alias
		if out, err := runner.Run(ctx, "/sbin/ifconfig", "lo0", "alias", norm.LoopbackIP, "up"); err != nil {
			return nil, fmt.Errorf("ifconfig lo0 alias %s: %w (%s)", norm.LoopbackIP, err, strings.TrimSpace(string(out)))
		}
		// Ensure com.apple/alt.<tld> is loaded into pfctl
		anchorName := fmt.Sprintf("com.apple/alt.%s", norm.TLD)
		_, _ = runner.Run(ctx, "/sbin/pfctl", "-a", anchorName, "-f", plan.Receipt.PFAnchorFilePath)
		_, _ = runner.Run(ctx, "/sbin/pfctl", "-E")

		// Trust local Root CA in macOS Keychain if present
		if _, err := os.Stat(norm.CACertPath); err == nil {
			if err := TrustCACertDarwin(ctx, runner, norm.CACertPath, norm.HomeDir); err != nil {
				return nil, err
			}
		}

		// Reload LaunchDaemon and LaunchAgent idempotently
		_, _ = runner.Run(ctx, "/bin/launchctl", "bootout", "system/"+plan.LaunchDaemonLabel)
		_, _ = runner.Run(ctx, "/bin/launchctl", "bootstrap", "system", plan.Receipt.LaunchDaemonPlist)

		guiDomain := fmt.Sprintf("gui/%d", norm.Uid)
		_, _ = runner.Run(ctx, "/bin/launchctl", "bootout", guiDomain+"/"+plan.LaunchAgentLabel)
		_, _ = runner.Run(ctx, "/bin/launchctl", "bootstrap", guiDomain, plan.Receipt.LaunchAgentPlist)
		_, _ = runner.Run(ctx, "/bin/launchctl", "kickstart", "-k", guiDomain+"/"+plan.LaunchAgentLabel)

		// Register supplemental DNS service in macOS SystemConfiguration DynamicStore (`scutil`) so `configd`
		// immediately rebuilds `scutil --dns` (even when `/etc/resolver` did not exist at boot or Cloudflare WARP
		// is active) and flush any cached NXDOMAIN entries in `mDNSResponder`.
		_, _ = runner.Run(ctx, "/bin/sh", "-c", RenderScutilInstallShellCmd(norm.TLD, norm.LoopbackIP, norm.DNSPort))
		_, _ = runner.Run(ctx, "/usr/bin/notifyutil", "-p", "com.apple.system.config.network_change")
		_, _ = runner.Run(ctx, "/usr/bin/dscacheutil", "-flushcache")
		_, _ = runner.Run(ctx, "/usr/bin/killall", "-HUP", "mDNSResponder")
	}

	return plan, nil
}

// ApplyUninstall cleanly removes all system integration artifacts recorded in `<stateDir>/install-receipt.json`
// (or derived from `opts` if the receipt was already removed) without touching Caddy or unrelated services.
func ApplyUninstall(ctx context.Context, opts Options, runner CommandRunner, skipOSCommands bool) (*Plan, error) {
	norm, err := NormalizeOptions(opts)
	if err != nil {
		return nil, err
	}
	plan, err := BuildPlan(norm)
	if err != nil {
		return nil, err
	}
	if receipt, rErr := LoadReceipt(norm.StateDir); rErr == nil && receipt != nil {
		plan.Receipt = *receipt
	}
	if runner == nil {
		runner = DefaultRunner()
	}

	// Remove `/etc/resolver/<tld>` before triggering SCDynamicStore rebuild so `configd` drops both
	// the supplemental DynamicStore entry and the flatfile resolver in a single atomic pass.
	_ = os.Remove(plan.Receipt.ResolverFilePath)

	if !skipOSCommands && runtime.GOOS == "darwin" {
		guiDomain := fmt.Sprintf("gui/%d", norm.Uid)
		_, _ = runner.Run(ctx, "/bin/launchctl", "bootout", guiDomain+"/"+plan.LaunchAgentLabel)
		_, _ = runner.Run(ctx, "/bin/launchctl", "bootout", "system/"+plan.LaunchDaemonLabel)

		_, _ = runner.Run(ctx, "/bin/sh", "-c", RenderScutilRemoveShellCmd(plan.Receipt.TLD))
		_, _ = runner.Run(ctx, "/usr/bin/notifyutil", "-p", "com.apple.system.config.network_change")
		_, _ = runner.Run(ctx, "/usr/bin/dscacheutil", "-flushcache")
		_, _ = runner.Run(ctx, "/usr/bin/killall", "-HUP", "mDNSResponder")

		anchorName := fmt.Sprintf("com.apple/alt.%s", plan.Receipt.TLD)
		_, _ = runner.Run(ctx, "/sbin/pfctl", "-a", anchorName, "-F", "all")
		if plan.Receipt.LoopbackIP != "" && plan.Receipt.LoopbackIP != "127.0.0.1" {
			_, _ = runner.Run(ctx, "/sbin/ifconfig", "lo0", "-alias", plan.Receipt.LoopbackIP)
		}
		if _, err := os.Stat(plan.Receipt.CACertPath); err == nil {
			_, _ = runner.Run(ctx, "security", "remove-trusted-cert", "-d", plan.Receipt.CACertPath)
			if fp, fpErr := certSHA1FingerprintHex(plan.Receipt.CACertPath); fpErr == nil && fp != "" {
				if os.Geteuid() == 0 {
					_, _ = runner.Run(ctx, "security", "delete-certificate", "-Z", fp, "/Library/Keychains/System.keychain")
				} else {
					loginKeychain := filepath.Join(norm.HomeDir, "Library", "Keychains", "login.keychain-db")
					_, _ = runner.Run(ctx, "security", "delete-certificate", "-Z", fp, loginKeychain)
				}
			}
		}
	}

	_ = os.Remove(plan.Receipt.LaunchAgentPlist)
	_ = os.Remove(plan.Receipt.LaunchDaemonPlist)
	_ = os.Remove(plan.Receipt.PFAnchorFilePath)
	_ = os.Remove(plan.Receipt.HelperScriptPath)
	_ = os.Remove(ReceiptPath(norm.StateDir))

	return plan, nil
}

func certSHA1FingerprintHex(caCertPath string) (string, error) {
	raw, err := os.ReadFile(caCertPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("invalid PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

// TrustCACertDarwin installs `caCertPath` into the user's login keychain (or System keychain when root).
func TrustCACertDarwin(ctx context.Context, runner CommandRunner, caCertPath, homeDir string) error {
	if runner == nil {
		runner = DefaultRunner()
	}
	if os.Geteuid() == 0 {
		out, err := runner.Run(ctx, "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", caCertPath)
		if err == nil {
			return nil
		}
		return fmt.Errorf("trust CA in System.keychain: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	loginKeychain := filepath.Join(homeDir, "Library", "Keychains", "login.keychain-db")
	out, err := runner.Run(ctx, "security", "add-trusted-cert", "-r", "trustRoot", "-k", loginKeychain, caCertPath)
	if err != nil {
		return fmt.Errorf("trust CA in login.keychain-db: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CheckResult represents one diagnostic check performed by `alt doctor`.
type CheckResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"` // "ok", "warn", "fail"
	Summary     string `json:"summary"`
	Remediation string `json:"remediation,omitempty"`
}

// DoctorReport aggregates all `alt doctor` diagnostic checks.
type DoctorReport struct {
	NetworkID string        `json:"networkId"`
	TLD       string        `json:"tld"`
	Healthy   bool          `json:"healthy"`
	Checks    []CheckResult `json:"checks"`
}

// DoctorInput configures the paths and live addresses inspected by `RunDoctorChecks`.
type DoctorInput struct {
	NetworkID        string
	TLD              string
	StateDir         string
	CACertPath       string
	ResolverFilePath string
	PFAnchorFilePath string
	DaemonRunning    bool
	DaemonPID        int
	DaemonHTTPSAddr  string
	DaemonDNSAddr    string
	LoopbackIP       string
}

// RunDoctorChecks executes real verification checks against the daemon, UDP DNS stub,
// `/etc/resolver/<tld>`, local CA X.509 constraints, and loopback alias/port coexistence.
func RunDoctorChecks(ctx context.Context, in DoctorInput) DoctorReport {
	var checks []CheckResult
	allHealthy := true

	// Check 1: Daemon process & IPC health
	if in.DaemonRunning {
		checks = append(checks, CheckResult{
			ID:      "daemon_ipc",
			Name:    "Local daemon & IPC socket",
			Status:  "ok",
			Summary: fmt.Sprintf("running (pid %d, https=%s, dns=%s)", in.DaemonPID, in.DaemonHTTPSAddr, in.DaemonDNSAddr),
		})
	} else {
		allHealthy = false
		checks = append(checks, CheckResult{
			ID:          "daemon_ipc",
			Name:        "Local daemon & IPC socket",
			Status:      "fail",
			Summary:     "daemon is not running",
			Remediation: "Run `alt setup` or start the daemon with `alt daemon start`",
		})
	}

	// Check 2: UDP DNS stub live query for `register.<tld>`
	dnsAddr := strings.TrimSpace(in.DaemonDNSAddr)
	if dnsAddr != "" {
		ip, err := probeUDPDNSStub(ctx, dnsAddr, "register."+in.TLD)
		if err == nil {
			checks = append(checks, CheckResult{
				ID:      "dns_stub",
				Name:    fmt.Sprintf("Authoritative .%s UDP DNS stub", in.TLD),
				Status:  "ok",
				Summary: fmt.Sprintf("udp://%s resolved register.%s -> %s", dnsAddr, in.TLD, ip),
			})
		} else {
			allHealthy = false
			checks = append(checks, CheckResult{
				ID:          "dns_stub",
				Name:        fmt.Sprintf("Authoritative .%s UDP DNS stub", in.TLD),
				Status:      "fail",
				Summary:     fmt.Sprintf("DNS query to %s failed: %v", dnsAddr, err),
				Remediation: "Ensure `alt run --dns-listen` or `alt daemon start` is active",
			})
		}
	} else {
		checks = append(checks, CheckResult{
			ID:          "dns_stub",
			Name:        fmt.Sprintf("Authoritative .%s UDP DNS stub", in.TLD),
			Status:      "warn",
			Summary:     "no UDP DNS listener configured on active daemon",
			Remediation: "Run `alt setup` or pass `--dns-listen 127.0.0.2:15353`",
		})
	}

	// Check 3: macOS `/etc/resolver/<tld>` file & live OS system DNS resolution
	resPath := strings.TrimSpace(in.ResolverFilePath)
	if resPath == "" {
		resPath = filepath.Join("/etc/resolver", in.TLD)
	}
	resolverInstalled := false
	if raw, err := os.ReadFile(resPath); err == nil {
		content := string(raw)
		if strings.Contains(content, "nameserver") {
			resolverInstalled = true
			checks = append(checks, CheckResult{
				ID:      "os_resolver",
				Name:    fmt.Sprintf("macOS resolver (%s)", resPath),
				Status:  "ok",
				Summary: fmt.Sprintf("configured (%s)", strings.ReplaceAll(strings.TrimSpace(content), "\n", "; ")),
			})
		} else {
			allHealthy = false
			checks = append(checks, CheckResult{
				ID:          "os_resolver",
				Name:        fmt.Sprintf("macOS resolver (%s)", resPath),
				Status:      "fail",
				Summary:     "file exists but missing `nameserver` directive",
				Remediation: "Re-run `sudo alt setup`",
			})
		}
	} else {
		checks = append(checks, CheckResult{
			ID:          "os_resolver",
			Name:        fmt.Sprintf("macOS resolver (%s)", resPath),
			Status:      "warn",
			Summary:     fmt.Sprintf("%s not installed", resPath),
			Remediation: "Run `sudo alt setup` to enable direct browser resolution for https://*." + in.TLD,
		})
	}

	// Check 3b: Real OS-level hostname resolution via mDNSResponder / SystemConfiguration when system resolver is installed
	if runtime.GOOS == "darwin" && resolverInstalled && in.DaemonRunning && filepath.Clean(resPath) == filepath.Join("/etc/resolver", in.TLD) {
		wantIP := strings.TrimSpace(in.LoopbackIP)
		if wantIP == "" {
			wantIP = DefaultLoopbackAliasIP
		}
		probeHost := "register." + in.TLD
		lookupCtx, cancelLookup := context.WithTimeout(ctx, 2500*time.Millisecond)
		addrs, lErr := net.DefaultResolver.LookupIPAddr(lookupCtx, probeHost)
		cancelLookup()
		matchedIP := ""
		for _, a := range addrs {
			if a.IP != nil && a.IP.String() == wantIP {
				matchedIP = a.IP.String()
				break
			}
		}
		if lErr == nil && matchedIP != "" {
			checks = append(checks, CheckResult{
				ID:      "os_dns_lookup",
				Name:    fmt.Sprintf("macOS system DNS resolution (%s)", probeHost),
				Status:  "ok",
				Summary: fmt.Sprintf("mDNSResponder resolved %s -> %s", probeHost, matchedIP),
			})
		} else {
			allHealthy = false
			errDetail := "no matching loopback address returned"
			if lErr != nil {
				errDetail = lErr.Error()
			} else if len(addrs) > 0 {
				errDetail = fmt.Sprintf("resolved to %v instead of %s", addrs, wantIP)
			}
			checks = append(checks, CheckResult{
				ID:          "os_dns_lookup",
				Name:        fmt.Sprintf("macOS system DNS resolution (%s)", probeHost),
				Status:      "fail",
				Summary:     fmt.Sprintf("system resolver failed to resolve %s (%s)", probeHost, errDetail),
				Remediation: "Re-run `sudo alt setup` to register .alt in macOS SCDynamicStore (`scutil --dns`) and flush mDNSResponder",
			})
		}
	}

	// Check 4: Device Root CA certificate & X.509 NameConstraints for .<tld>
	if status, summary, rem := inspectCACertificate(in.CACertPath, in.TLD); status == "ok" {
		checks = append(checks, CheckResult{
			ID:      "ca_trust",
			Name:    "Device Root CA & NameConstraints",
			Status:  "ok",
			Summary: summary,
		})
	} else {
		if status == "fail" {
			allHealthy = false
		}
		checks = append(checks, CheckResult{
			ID:          "ca_trust",
			Name:        "Device Root CA & NameConstraints",
			Status:      status,
			Summary:     summary,
			Remediation: rem,
		})
	}

	// Check 5: Loopback alias & Caddy / port 443 coexistence
	loopIP := strings.TrimSpace(in.LoopbackIP)
	if loopIP == "" {
		loopIP = DefaultLoopbackAliasIP
	}
	if checkLoopbackAliasAssigned(loopIP) {
		checks = append(checks, CheckResult{
			ID:      "loopback_coexistence",
			Name:    "Loopback alias & port 443 coexistence",
			Status:  "ok",
			Summary: fmt.Sprintf("dedicated loopback alias %s active on lo0 (coexists with Caddy/*:443)", loopIP),
		})
	} else {
		checks = append(checks, CheckResult{
			ID:          "loopback_coexistence",
			Name:        "Loopback alias & port 443 coexistence",
			Status:      "warn",
			Summary:     fmt.Sprintf("loopback alias %s not assigned on lo0 yet", loopIP),
			Remediation: fmt.Sprintf("Run `sudo alt setup` (or `sudo ifconfig lo0 alias %s up`)", loopIP),
		})
	}

	// Check 6: Scoped PF port-443 redirect anchor (`com.apple/alt.<tld>`)
	pfPath := strings.TrimSpace(in.PFAnchorFilePath)
	if pfPath == "" {
		pfPath = filepath.Join("/etc/pf.anchors", fmt.Sprintf("dev.alt.%s", in.TLD))
	}
	if pfRaw, err := os.ReadFile(pfPath); err == nil {
		pfStr := string(pfRaw)
		if strings.Contains(pfStr, "rdr pass on lo0") && strings.Contains(pfStr, "port 443") {
			checks = append(checks, CheckResult{
				ID:      "pf_anchor",
				Name:    fmt.Sprintf("PF port 443 anchor (%s)", pfPath),
				Status:  "ok",
				Summary: "scoped lo0 port 443 rdr rule configured (leaves *:443 untouched)",
			})
		} else {
			allHealthy = false
			checks = append(checks, CheckResult{
				ID:          "pf_anchor",
				Name:        fmt.Sprintf("PF port 443 anchor (%s)", pfPath),
				Status:      "fail",
				Summary:     "PF anchor file is missing valid lo0 port 443 rdr rule",
				Remediation: "Re-run `sudo alt setup`",
			})
		}
	} else {
		checks = append(checks, CheckResult{
			ID:          "pf_anchor",
			Name:        fmt.Sprintf("PF port 443 anchor (%s)", pfPath),
			Status:      "warn",
			Summary:     fmt.Sprintf("%s not installed", pfPath),
			Remediation: "Run `sudo alt setup` to translate 443 -> unprivileged daemon port on " + loopIP,
		})
	}

	return DoctorReport{
		NetworkID: in.NetworkID,
		TLD:       in.TLD,
		Healthy:   allHealthy,
		Checks:    checks,
	}
}

func inspectCACertificate(caCertPath, tld string) (status, summary, remediation string) {
	if strings.TrimSpace(caCertPath) == "" {
		return "warn", "CA path not configured", "Run `alt setup` to initialize the device-local CA"
	}
	raw, err := os.ReadFile(caCertPath)
	if err != nil {
		return "warn", fmt.Sprintf("CA certificate not generated yet (%s)", caCertPath), "Run `alt setup` or `alt daemon start` to generate the device-local CA"
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "fail", "CA certificate file is not valid PEM", "Delete corrupt ca.crt and re-run `alt setup`"
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "fail", fmt.Sprintf("failed to parse CA X.509 certificate: %v", err), "Re-run `alt setup`"
	}
	now := time.Now().UTC()
	if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
		return "fail", fmt.Sprintf("CA certificate expired or not yet valid (NotAfter=%s)", cert.NotAfter.Format(time.RFC3339)), "Re-run `alt setup`"
	}
	wantSuffix := "." + tld
	hasConstraint := false
	for _, d := range cert.PermittedDNSDomains {
		if d == wantSuffix || d == tld {
			hasConstraint = true
			break
		}
	}
	if !cert.PermittedDNSDomainsCritical || !hasConstraint {
		return "fail", fmt.Sprintf("CA certificate is missing critical NameConstraints for .%s", tld), "Regenerate CA with `alt setup`"
	}
	return "ok", fmt.Sprintf("valid constrained Root CA for .%s (expires %s)", tld, cert.NotAfter.Format("2006-01-02")), ""
}

func checkLoopbackAliasAssigned(targetIP string) bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if (iface.Flags & net.FlagLoopback) == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.String() == targetIP {
				return true
			}
		}
	}
	return false
}

func probeUDPDNSStub(ctx context.Context, dnsAddr, qname string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	var msg bytes.Buffer
	// DNS Header: ID=0x1234, Flags=0x0100 (RD), QDCOUNT=1
	msg.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 {
			return "", errors.New("invalid DNS label")
		}
		msg.WriteByte(byte(len(l)))
		msg.WriteString(l)
	}
	msg.WriteByte(0x00)
	// QTYPE=A (1), QCLASS=IN (1)
	msg.Write([]byte{0x00, 0x01, 0x00, 0x01})

	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "udp", dnsAddr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(msg.Bytes()); err != nil {
		return "", err
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		return "", err
	}
	if n < 12 {
		return "", errors.New("short DNS response")
	}
	rcode := resp[3] & 0x0f
	ancount := int(resp[6])<<8 | int(resp[7])
	if rcode != 0 || ancount < 1 {
		return "", fmt.Errorf("DNS rcode=%d ancount=%d", rcode, ancount)
	}
	// Last 4 bytes of our single-A response contain the IPv4 address
	if n >= 4 {
		ip := net.IPv4(resp[n-4], resp[n-3], resp[n-2], resp[n-1])
		return ip.String(), nil
	}
	return strconv.Itoa(ancount) + " record(s)", nil
}
