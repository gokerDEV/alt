// Package sysinstall implements idempotent, reversible macOS system integration
// for the ALT local resolver and non-root loopback HTTPS daemon.
//
// Coexistence architecture (Caddy / local web server safety):
//   - dotALT allocates a dedicated loopback alias (default 127.0.0.2 on lo0) rather than
//     competing with servers listening on 127.0.0.1:443 or *:443.
//   - The unprivileged user LaunchAgent (`dev.alt.daemon`) binds high loopback ports
//     (`127.0.0.2:9443` for HTTPS and `127.0.0.2:15353` for the authoritative `.alt` UDP DNS stub).
//   - `/etc/resolver/<tld>` routes ONLY `.alt` queries to `127.0.0.2:15353`, which returns `127.0.0.2`.
//   - A scoped PF anchor (`com.apple/alt.<tld>`) translates `127.0.0.2:443 -> 127.0.0.2:9443`
//     on `lo0` before any wildcard `*:443` listener (such as Caddy) sees the packet.
//   - Caddy and other local servers on `*:443` or `127.0.0.1:443` remain 100% untouched.
package sysinstall

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"alt/pkg/names"
)

const (
	// DefaultLoopbackAliasIP is the dedicated lo0 alias IP used by dotALT so it never collides with 127.0.0.1.
	DefaultLoopbackAliasIP = "127.0.0.2"

	// DefaultDaemonHTTPSPort is the unprivileged loopback HTTPS port bound by the user daemon.
	DefaultDaemonHTTPSPort = 9443

	// DefaultDaemonDNSPort is the unprivileged loopback UDP DNS stub port bound by the user daemon.
	DefaultDaemonDNSPort = 15353

	// MinSupportedMacOSMajor is the minimum macOS major version supported by the LaunchAgent/PF installer.
	MinSupportedMacOSMajor = 12

	// SchemaInstallStateV1 identifies the persisted installation receipt format.
	SchemaInstallStateV1 = "alt.install-state.v1"
)

// TargetUser describes the unprivileged OS user account whose LaunchAgent and state directory own the daemon.
type TargetUser struct {
	Uid       int
	Gid       int
	Username  string
	HomeDir   string
	ConfigDir string
}

// ResolveTargetUser resolves the real non-root user when `sudo alt setup` or a macOS `.pkg` postinstall
// script runs as root, ensuring user state, CA keys, and LaunchAgents are never mistakenly placed in `/var/root`.
func ResolveTargetUser(explicitUser string) (TargetUser, error) {
	lookup := func(u *user.User) (TargetUser, error) {
		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return TargetUser{}, fmt.Errorf("sysinstall: parse uid %q: %w", u.Uid, err)
		}
		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			return TargetUser{}, fmt.Errorf("sysinstall: parse gid %q: %w", u.Gid, err)
		}
		cfgDir := filepath.Join(u.HomeDir, ".config")
		if runtime.GOOS == "darwin" {
			cfgDir = filepath.Join(u.HomeDir, "Library", "Application Support")
		}
		if envCfg := strings.TrimSpace(os.Getenv("ALT_CONFIG_DIR")); envCfg != "" {
			cfgDir = envCfg
		}
		return TargetUser{
			Uid:       uid,
			Gid:       gid,
			Username:  u.Username,
			HomeDir:   u.HomeDir,
			ConfigDir: cfgDir,
		}, nil
	}

	if trimmed := strings.TrimSpace(explicitUser); trimmed != "" {
		u, err := user.Lookup(trimmed)
		if err != nil {
			return TargetUser{}, fmt.Errorf("sysinstall: lookup user %q: %w", trimmed, err)
		}
		return lookup(u)
	}

	if os.Geteuid() == 0 {
		if sudoUID := strings.TrimSpace(os.Getenv("SUDO_UID")); sudoUID != "" && sudoUID != "0" {
			if u, err := user.LookupId(sudoUID); err == nil {
				return lookup(u)
			}
		}
		if sudoUser := strings.TrimSpace(os.Getenv("SUDO_USER")); sudoUser != "" && sudoUser != "root" {
			if u, err := user.Lookup(sudoUser); err == nil {
				return lookup(u)
			}
		}
		if runtime.GOOS == "darwin" {
			if st, err := os.Stat("/dev/console"); err == nil {
				if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid > 0 {
					if u, uErr := user.LookupId(strconv.Itoa(int(sys.Uid))); uErr == nil {
						return lookup(u)
					}
				}
			}
		}
	}

	if u, err := user.Current(); err == nil {
		return lookup(u)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return TargetUser{}, err
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		cfgDir = filepath.Join(home, "Library", "Application Support")
	}
	return TargetUser{
		Uid:       os.Getuid(),
		Gid:       os.Getgid(),
		HomeDir:   home,
		ConfigDir: cfgDir,
	}, nil
}

// Options configures a macOS system setup or uninstall operation.
type Options struct {
	TLD              string
	NetworkID        string
	BinaryPath       string
	StateDir         string
	CACertPath       string
	LoopbackIP       string
	HTTPSPort        int
	DNSPort          int
	Uid              int
	Gid              int
	HomeDir          string
	ResolverDir      string // Defaults to "/etc/resolver"
	PFAnchorsDir     string // Defaults to "/etc/pf.anchors"
	LaunchDaemonsDir string // Defaults to "/Library/LaunchDaemons"
	LaunchAgentsDir  string // Defaults to "<HomeDir>/Library/LaunchAgents"
	SystemSupportDir string // Root-owned helper dir; defaults to "/Library/Application Support/alt"
}

// InstallReceipt records the installed system artifacts inside `<stateDir>/install-receipt.json`
// so `alt status`, `alt doctor`, and `alt uninstall` can inspect and cleanly reverse every step.
type InstallReceipt struct {
	Schema            string `json:"schema"`
	Version           int    `json:"version"`
	InstalledAt       string `json:"installedAt"`
	NetworkID         string `json:"networkId"`
	TLD               string `json:"tld"`
	LoopbackIP        string `json:"loopbackIp"`
	HTTPSPort         int    `json:"httpsPort"`
	DNSPort           int    `json:"dnsPort"`
	BinaryPath        string `json:"binaryPath"`
	CACertPath        string `json:"caCertPath"`
	ResolverFilePath  string `json:"resolverFilePath"`
	PFAnchorFilePath  string `json:"pfAnchorFilePath"`
	HelperScriptPath  string `json:"helperScriptPath"`
	LaunchDaemonPlist string `json:"launchDaemonPlist"`
	LaunchAgentPlist  string `json:"launchAgentPlist"`
}

// Plan holds the deterministic file paths and rendered contents for a system installation.
type Plan struct {
	Receipt           InstallReceipt
	ResolverContent   string
	PFAnchorContent   string
	HelperScript      string
	LaunchDaemonXML   string
	LaunchAgentXML    string
	LaunchDaemonLabel string
	LaunchAgentLabel  string
}

// NormalizeOptions validates and fills default paths and ports for Options.
func NormalizeOptions(opts Options) (Options, error) {
	tld, err := names.NormalizeTLD(opts.TLD)
	if err != nil {
		return opts, err
	}
	opts.TLD = tld

	if strings.TrimSpace(opts.NetworkID) == "" {
		opts.NetworkID = "alt-main-v1"
	}
	if strings.TrimSpace(opts.LoopbackIP) == "" {
		opts.LoopbackIP = DefaultLoopbackAliasIP
	}
	ip := net.ParseIP(opts.LoopbackIP)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() || ip.String() == "127.0.0.1" {
		return opts, fmt.Errorf("sysinstall: loopback IP %q must be a dedicated IPv4 loopback alias other than 127.0.0.1 (e.g. 127.0.0.2)", opts.LoopbackIP)
	}
	opts.LoopbackIP = ip.String()

	if opts.HTTPSPort <= 0 {
		opts.HTTPSPort = DefaultDaemonHTTPSPort
	}
	if opts.HTTPSPort < 1024 || opts.HTTPSPort > 65535 {
		return opts, fmt.Errorf("sysinstall: HTTPS daemon port %d must be an unprivileged port (1024..65535)", opts.HTTPSPort)
	}
	if opts.DNSPort <= 0 {
		opts.DNSPort = DefaultDaemonDNSPort
	}
	if opts.DNSPort < 1024 || opts.DNSPort > 65535 {
		return opts, fmt.Errorf("sysinstall: DNS stub port %d must be an unprivileged port (1024..65535)", opts.DNSPort)
	}
	if opts.HTTPSPort == opts.DNSPort {
		return opts, errors.New("sysinstall: HTTPS port and DNS port must be distinct")
	}

	if opts.Uid <= 0 || strings.TrimSpace(opts.HomeDir) == "" {
		if tu, uErr := ResolveTargetUser(""); uErr == nil {
			if opts.Uid <= 0 {
				opts.Uid = tu.Uid
			}
			if opts.Gid <= 0 {
				opts.Gid = tu.Gid
			}
			if strings.TrimSpace(opts.HomeDir) == "" {
				opts.HomeDir = tu.HomeDir
			}
		} else {
			if opts.Uid <= 0 {
				opts.Uid = os.Getuid()
			}
			if opts.Gid <= 0 {
				opts.Gid = os.Getgid()
			}
			if strings.TrimSpace(opts.HomeDir) == "" {
				home, err := os.UserHomeDir()
				if err != nil {
					return opts, err
				}
				opts.HomeDir = home
			}
		}
	}
	if opts.Gid <= 0 {
		opts.Gid = os.Getgid()
	}
	if strings.TrimSpace(opts.StateDir) == "" {
		return opts, errors.New("sysinstall: StateDir is required")
	}
	absState, err := filepath.Abs(opts.StateDir)
	if err != nil {
		return opts, err
	}
	opts.StateDir = absState

	if strings.TrimSpace(opts.CACertPath) == "" {
		opts.CACertPath = filepath.Join(opts.StateDir, "pki", "ca.crt")
	}
	if strings.TrimSpace(opts.BinaryPath) == "" {
		exe, err := os.Executable()
		if err != nil {
			return opts, err
		}
		opts.BinaryPath = exe
	}
	absBin, err := filepath.Abs(opts.BinaryPath)
	if err != nil {
		return opts, err
	}
	opts.BinaryPath = absBin

	if strings.TrimSpace(opts.ResolverDir) == "" {
		opts.ResolverDir = "/etc/resolver"
	}
	if strings.TrimSpace(opts.PFAnchorsDir) == "" {
		opts.PFAnchorsDir = "/etc/pf.anchors"
	}
	if strings.TrimSpace(opts.LaunchDaemonsDir) == "" {
		opts.LaunchDaemonsDir = "/Library/LaunchDaemons"
	}
	if strings.TrimSpace(opts.LaunchAgentsDir) == "" {
		opts.LaunchAgentsDir = filepath.Join(opts.HomeDir, "Library", "LaunchAgents")
	}
	if strings.TrimSpace(opts.SystemSupportDir) == "" {
		// Derive root-owned support dir alongside LaunchDaemonsDir ("/Library/Application Support/alt" in prod,
		// or "<tmp>/Library/Application Support/alt" in sandboxed unit tests) so root LaunchDaemons never run user-writable scripts.
		opts.SystemSupportDir = filepath.Join(filepath.Dir(opts.LaunchDaemonsDir), "Application Support", "alt")
	}

	return opts, nil
}

// BuildPlan constructs the exact, deterministic configuration artifacts for `opts`.
func BuildPlan(opts Options) (*Plan, error) {
	norm, err := NormalizeOptions(opts)
	if err != nil {
		return nil, err
	}

	daemonLabel := fmt.Sprintf("dev.alt.nethelper.%s", norm.TLD)
	agentLabel := fmt.Sprintf("dev.alt.daemon.%s", norm.TLD)

	resolverFile := filepath.Join(norm.ResolverDir, norm.TLD)
	pfAnchorFile := filepath.Join(norm.PFAnchorsDir, fmt.Sprintf("dev.alt.%s", norm.TLD))
	helperScriptPath := filepath.Join(norm.SystemSupportDir, "bin", fmt.Sprintf("alt-nethelper-%s.sh", norm.TLD))
	daemonPlist := filepath.Join(norm.LaunchDaemonsDir, daemonLabel+".plist")
	agentPlist := filepath.Join(norm.LaunchAgentsDir, agentLabel+".plist")

	resolverContent := RenderResolverFile(norm.TLD, norm.LoopbackIP, norm.DNSPort)
	pfAnchorContent := RenderPFAnchorWithDNS(norm.TLD, norm.LoopbackIP, norm.HTTPSPort, norm.DNSPort)
	helperScript := RenderNetHelperScriptWithDNS(norm.TLD, norm.LoopbackIP, norm.DNSPort, pfAnchorFile)

	daemonXML, err := RenderLaunchDaemonPlist(daemonLabel, helperScriptPath)
	if err != nil {
		return nil, err
	}
	agentXML, err := RenderLaunchAgentPlist(agentLabel, norm)
	if err != nil {
		return nil, err
	}

	receipt := InstallReceipt{
		Schema:            SchemaInstallStateV1,
		Version:           1,
		InstalledAt:       time.Now().UTC().Format(time.RFC3339),
		NetworkID:         norm.NetworkID,
		TLD:               norm.TLD,
		LoopbackIP:        norm.LoopbackIP,
		HTTPSPort:         norm.HTTPSPort,
		DNSPort:           norm.DNSPort,
		BinaryPath:        norm.BinaryPath,
		CACertPath:        norm.CACertPath,
		ResolverFilePath:  resolverFile,
		PFAnchorFilePath:  pfAnchorFile,
		HelperScriptPath:  helperScriptPath,
		LaunchDaemonPlist: daemonPlist,
		LaunchAgentPlist:  agentPlist,
	}

	return &Plan{
		Receipt:           receipt,
		ResolverContent:   resolverContent,
		PFAnchorContent:   pfAnchorContent,
		HelperScript:      helperScript,
		LaunchDaemonXML:   daemonXML,
		LaunchAgentXML:    agentXML,
		LaunchDaemonLabel: daemonLabel,
		LaunchAgentLabel:  agentLabel,
	}, nil
}

// RenderResolverFile renders the macOS `/etc/resolver/<tld>` configuration file.
func RenderResolverFile(tld, loopbackIP string, dnsPort int) string {
	return fmt.Sprintf("# Generated by alt setup for .%s (do not edit manually)\ndomain %s\nnameserver %s\nport %d\ntimeout 2\nsearch_order 1\n",
		tld, tld, loopbackIP, dnsPort)
}

// RenderPFAnchor renders the isolated PF rdr rule translating `<loopbackIP>:443 -> <loopbackIP>:<httpsPort>` on `lo0`.
func RenderPFAnchor(tld, loopbackIP string, httpsPort int) string {
	return RenderPFAnchorWithDNS(tld, loopbackIP, httpsPort, DefaultDaemonDNSPort)
}

// RenderPFAnchorWithDNS renders isolated `lo0` PF rdr rules scoped strictly to `<loopbackIP>` for
// standard DNS port 53 (UDP/TCP -> `<dnsPort>`) and HTTPS port 443 (TCP -> `<httpsPort>`), leaving
// `127.0.0.1`, `127.0.2.2` (Cloudflare WARP), and `*:443` (Caddy) completely untouched.
func RenderPFAnchorWithDNS(tld, loopbackIP string, httpsPort, dnsPort int) string {
	return fmt.Sprintf("# Generated by alt setup for .%s — coexists with Caddy/*:443 and VPN DNS by scoping strictly to %s on lo0\n"+
		"rdr pass on lo0 inet proto udp from any to %s port 53 -> %s port %d\n"+
		"rdr pass on lo0 inet proto tcp from any to %s port 53 -> %s port %d\n"+
		"rdr pass on lo0 inet proto tcp from any to %s port 443 -> %s port %d\n",
		tld, loopbackIP,
		loopbackIP, loopbackIP, dnsPort,
		loopbackIP, loopbackIP, dnsPort,
		loopbackIP, loopbackIP, httpsPort)
}

// RenderScutilInstallShellCmd returns the idempotent `scutil` shell snippet that registers a supplemental
// macOS SystemConfiguration DNS service (`State:/Network/Service/dev.alt.<tld>/DNS`) so `configd` and
// `mDNSResponder` immediately route `*.<tld>` to `<loopbackIP>:<dnsPort>` even when `/etc/resolver` did not
// exist at boot or when VPN split-DNS clients (e.g. Cloudflare WARP) are active.
func RenderScutilInstallShellCmd(tld, loopbackIP string, dnsPort int) string {
	serviceKey := fmt.Sprintf("State:/Network/Service/dev.alt.%s/DNS", tld)
	return fmt.Sprintf(`/usr/sbin/scutil <<'EOF'
open
d.init
d.add ServerAddresses * %s
d.add ServerPort # %d
d.add SupplementalMatchDomains * %s
d.add SupplementalMatchDomainsNoSearch # 1
d.add ServerTimeout # 2
set %s
quit
EOF`, loopbackIP, dnsPort, tld, serviceKey)
}

// RenderScutilRemoveShellCmd removes `State:/Network/Service/dev.alt.<tld>/DNS` from `SCDynamicStore`.
func RenderScutilRemoveShellCmd(tld string) string {
	serviceKey := fmt.Sprintf("State:/Network/Service/dev.alt.%s/DNS", tld)
	return fmt.Sprintf(`/usr/sbin/scutil <<'EOF'
open
remove %s
quit
EOF`, serviceKey)
}

// RenderNetHelperScript renders the idempotent script executed at boot by the LaunchDaemon.
func RenderNetHelperScript(tld, loopbackIP, pfAnchorFile string) string {
	return RenderNetHelperScriptWithDNS(tld, loopbackIP, DefaultDaemonDNSPort, pfAnchorFile)
}

// RenderNetHelperScriptWithDNS renders the idempotent root boot script executed by the LaunchDaemon
// to ensure the `lo0` alias, PF anchor rules, and `SCDynamicStore` supplemental DNS service are active.
func RenderNetHelperScriptWithDNS(tld, loopbackIP string, dnsPort int, pfAnchorFile string) string {
	anchorName := fmt.Sprintf("com.apple/alt.%s", tld)
	scutilCmd := RenderScutilInstallShellCmd(tld, loopbackIP, dnsPort)
	return fmt.Sprintf(`#!/bin/sh
set -eu
/sbin/ifconfig lo0 alias %s up
/sbin/pfctl -a %s -f %s >/dev/null 2>&1 || true
/sbin/pfctl -E >/dev/null 2>&1 || true
%s >/dev/null 2>&1 || true
/usr/bin/notifyutil -p com.apple.system.config.network_change >/dev/null 2>&1 || true
/usr/bin/dscacheutil -flushcache >/dev/null 2>&1 || true
/usr/bin/killall -HUP mDNSResponder >/dev/null 2>&1 || true
`, loopbackIP, anchorName, pfAnchorFile, scutilCmd)
}

type plistDict struct {
	XMLName xml.Name
	Entries []any
}

// RenderLaunchDaemonPlist renders the boot-time LaunchDaemon plist for configuring the `lo0` alias and PF anchor.
func RenderLaunchDaemonPlist(label, helperScriptPath string) (string, error) {
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	writePlistKeyString(&b, "Label", label)
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	writePlistArrayString(&b, "/bin/sh")
	writePlistArrayString(&b, helperScriptPath)
	b.WriteString("  </array>\n")
	writePlistKeyBool(&b, "RunAtLoad", true)
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

// RenderLaunchAgentPlist renders the unprivileged user LaunchAgent plist that runs `alt run` in daemon mode.
func RenderLaunchAgentPlist(label string, opts Options) (string, error) {
	httpsListen := net.JoinHostPort(opts.LoopbackIP, strconv.Itoa(opts.HTTPSPort))
	dnsListen := net.JoinHostPort(opts.LoopbackIP, strconv.Itoa(opts.DNSPort))
	logPath := filepath.Join(opts.StateDir, "logs", "daemon.log")

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	writePlistKeyString(&b, "Label", label)
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	writePlistArrayString(&b, opts.BinaryPath)
	writePlistArrayString(&b, "run")
	writePlistArrayString(&b, "--daemon")
	writePlistArrayString(&b, "--listen")
	writePlistArrayString(&b, httpsListen)
	writePlistArrayString(&b, "--dns-listen")
	writePlistArrayString(&b, dnsListen)
	writePlistArrayString(&b, "--tld")
	writePlistArrayString(&b, opts.TLD)
	writePlistArrayString(&b, "--state-dir")
	writePlistArrayString(&b, opts.StateDir)
	b.WriteString("  </array>\n")
	writePlistKeyBool(&b, "RunAtLoad", true)
	writePlistKeyBool(&b, "KeepAlive", true)
	writePlistKeyString(&b, "StandardOutPath", logPath)
	writePlistKeyString(&b, "StandardErrorPath", logPath)
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

func writePlistKeyString(b *bytes.Buffer, key, val string) {
	b.WriteString("  <key>")
	_ = xml.EscapeText(b, []byte(key))
	b.WriteString("</key>\n  <string>")
	_ = xml.EscapeText(b, []byte(val))
	b.WriteString("</string>\n")
}

func writePlistArrayString(b *bytes.Buffer, val string) {
	b.WriteString("    <string>")
	_ = xml.EscapeText(b, []byte(val))
	b.WriteString("</string>\n")
}

func writePlistKeyBool(b *bytes.Buffer, key string, val bool) {
	b.WriteString("  <key>")
	_ = xml.EscapeText(b, []byte(key))
	if val {
		b.WriteString("</key>\n  <true/>\n")
	} else {
		b.WriteString("</key>\n  <false/>\n")
	}
}

// ReceiptPath returns `<stateDir>/install-receipt.json`.
func ReceiptPath(stateDir string) string {
	return filepath.Join(stateDir, "install-receipt.json")
}

// SaveReceipt writes the installation receipt atomically to `<stateDir>/install-receipt.json`.
func SaveReceipt(stateDir string, receipt InstallReceipt) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	path := ReceiptPath(stateDir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, encoded, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadReceipt reads `<stateDir>/install-receipt.json` if present.
func LoadReceipt(stateDir string) (*InstallReceipt, error) {
	raw, err := os.ReadFile(ReceiptPath(stateDir))
	if err != nil {
		return nil, err
	}
	var r InstallReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
