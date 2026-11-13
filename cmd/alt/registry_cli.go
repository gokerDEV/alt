package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"alt/pkg/names"
	"alt/pkg/profile"
	"alt/pkg/records"
)

const (
	defaultRegistryBaseURL = "https://alt.goker.dev"
	keychainServicePrefix  = "alt-cli"
)

type apiErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type accountSummary struct {
	ID             string  `json:"id"`
	GitHubID       string  `json:"githubId"`
	GitHubLogin    string  `json:"githubLogin"`
	AvatarURL      *string `json:"avatarUrl"`
	OwnerPublicKey *string `json:"ownerPublicKey"`
}

type domainSummary struct {
	Name              string                        `json:"name"`
	Label             string                        `json:"label"`
	Kind              string                        `json:"kind"`
	Status            string                        `json:"status"`
	Generation        uint64                        `json:"generation"`
	Sequence          uint64                        `json:"sequence"`
	OwnerPublicKey    *string                       `json:"ownerPublicKey"`
	OwnershipRecord   *records.OwnershipCertificate `json:"ownershipRecord"`
	TargetRecord      *records.TargetRecord         `json:"targetRecord"`
	PublicationStatus string                        `json:"publicationStatus"`
	ManifestCID       *string                       `json:"manifestCid"`
	PublishedAt       *string                       `json:"publishedAt"`
}

type accountResponse struct {
	Account accountSummary `json:"account"`
	Domain  *domainSummary `json:"domain"`
	Network struct {
		NetworkID           string `json:"networkId"`
		TLD                 string `json:"tld"`
		RegistrationEnabled bool   `json:"registrationEnabled"`
	} `json:"network"`
}

type cliSessionExchangeResponse struct {
	Token     string         `json:"token"`
	ExpiresAt string         `json:"expiresAt"`
	Account   accountSummary `json:"account"`
}

type keyChallengeResponse struct {
	NetworkID string `json:"networkId"`
	AccountID string `json:"accountId"`
	Nonce     string `json:"nonce"`
	Purpose   string `json:"purpose"`
	ExpiresAt string `json:"expiresAt"`
}

type keyVerifyResponse struct {
	Account accountSummary `json:"account"`
	Domain  *domainSummary `json:"domain"`
}

type registerDomainResponse struct {
	Domain domainSummary `json:"domain"`
}

type publishTargetResponse struct {
	Domain      domainSummary `json:"domain"`
	Publication struct {
		Status      string  `json:"status"`
		ManifestCID *string `json:"manifestCid"`
		IPNSName    *string `json:"ipnsName"`
		Error       *string `json:"error"`
	} `json:"publication"`
}

func resolveRegistryBaseURL(flagVal string) (string, error) {
	raw := strings.TrimSpace(flagVal)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("ALT_REGISTRY_URL"))
	}
	if raw == "" {
		raw = defaultRegistryBaseURL
	}
	raw = strings.TrimRight(raw, "/")

	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("invalid registry URL %q", raw)
	}
	host := u.Hostname()
	if u.Scheme == "http" && host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return "", fmt.Errorf("plaintext http:// registry URL is only permitted on loopback (got %q)", raw)
	}
	return raw, nil
}

func resolveStateBaseDir(flagVal, networkID string) (string, error) {
	if strings.TrimSpace(flagVal) != "" {
		return filepath.Abs(flagVal)
	}
	if envDir := strings.TrimSpace(os.Getenv("ALT_CONFIG_DIR")); envDir != "" {
		return filepath.Join(envDir, "networks", networkID), nil
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(cfgDir, "alt", "networks", networkID), nil
}

// secretStore persists sensitive CLI tokens and owner Ed25519 private keys in the OS credential store
// (macOS Keychain via `security`) when available, falling back to a `0600` file inside a `0700` directory (§4.2, §4.3).
func writeSecret(stateDir, name, secretValue string) (string, error) {
	if os.Getenv("ALT_DISABLE_KEYCHAIN") != "1" && runtime.GOOS == "darwin" {
		service := keychainServicePrefix + ":" + filepath.Base(stateDir) + ":" + name
		cmd := exec.Command("security", "add-generic-password", "-U", "-a", "alt", "-s", service, "-w", secretValue)
		if err := cmd.Run(); err == nil {
			// Remove any stale fallback file if keychain succeeded
			_ = os.Remove(filepath.Join(stateDir, name))
			return "macos-keychain", nil
		}
	}

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return "", err
	}
	_ = os.Chmod(stateDir, 0o700)

	filePath := filepath.Join(stateDir, name)
	tmpPath := filePath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(secretValue+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	if err := os.Rename(tmpPath, filePath); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return filePath, nil
}

func readSecret(stateDir, name string) (string, error) {
	if os.Getenv("ALT_DISABLE_KEYCHAIN") != "1" && runtime.GOOS == "darwin" {
		service := keychainServicePrefix + ":" + filepath.Base(stateDir) + ":" + name
		out, err := exec.Command("security", "find-generic-password", "-a", "alt", "-s", service, "-w").Output()
		if err == nil {
			if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
				return trimmed, nil
			}
		}
	}

	filePath := filepath.Join(stateDir, name)
	st, err := os.Lstat(filePath)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("refusing non-regular secret file %s", filePath)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("refusing secret file %s with insecure permissions %04o (expected 0600)", filePath, st.Mode().Perm())
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return "", os.ErrNotExist
	}
	return trimmed, nil
}

func deleteSecret(stateDir, name string) {
	if os.Getenv("ALT_DISABLE_KEYCHAIN") != "1" && runtime.GOOS == "darwin" {
		service := keychainServicePrefix + ":" + filepath.Base(stateDir) + ":" + name
		_ = exec.Command("security", "delete-generic-password", "-a", "alt", "-s", service).Run()
	}
	_ = os.Remove(filepath.Join(stateDir, name))
}

func loadOrCreateOwnerKey(stateDir, accountID string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	safeAcct := strings.NewReplacer(":", "_", "/", "_").Replace(accountID)
	secretName := "owner-" + safeAcct + ".key"

	if existing, err := readSecret(stateDir, secretName); err == nil {
		raw, decErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(existing, records.Ed25519KeyPrefix))
		if decErr != nil {
			return nil, nil, fmt.Errorf("decode stored owner key: %w", decErr)
		}
		var priv ed25519.PrivateKey
		switch len(raw) {
		case ed25519.SeedSize:
			priv = ed25519.NewKeyFromSeed(raw)
		case ed25519.PrivateKeySize:
			priv = ed25519.PrivateKey(raw)
		default:
			return nil, nil, fmt.Errorf("invalid stored owner private key byte length %d", len(raw))
		}
		return priv.Public().(ed25519.PublicKey), priv, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate owner Ed25519 key: %w", err)
	}
	encodedPriv := base64.StdEncoding.EncodeToString(priv)
	if _, err := writeSecret(stateDir, secretName, encodedPriv); err != nil {
		return nil, nil, fmt.Errorf("store owner Ed25519 key: %w", err)
	}
	return pub, priv, nil
}

func registryJSONRequest(
	ctx context.Context,
	client *http.Client,
	method, fullURL, bearerToken string,
	reqBody any,
	respDst any,
) (int, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return 0, err
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "alt-cli/0.2")
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return resp.StatusCode, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr apiErrorEnvelope
		if json.Unmarshal(rawResp, &apiErr) == nil && apiErr.Error.Message != "" {
			return resp.StatusCode, fmt.Errorf("[%s] %s (HTTP %d)", apiErr.Error.Code, apiErr.Error.Message, resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("registry HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}

	if respDst != nil && len(rawResp) > 0 {
		if err := json.Unmarshal(rawResp, respDst); err != nil {
			return resp.StatusCode, fmt.Errorf("decode registry response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

type githubDeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
}

type githubDeviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Interval    int    `json:"interval"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

func runGitHubDeviceFlow(
	ctx context.Context,
	client *http.Client,
	githubBaseURL string,
	clientID string,
	out io.Writer,
) (string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", errors.New("GitHub OAuth Client ID is required (pass --client-id or set ALT_GITHUB_CLIENT_ID / GITHUB_CLIENT_ID)")
	}
	ghBase := strings.TrimRight(githubBaseURL, "/")
	if ghBase == "" {
		ghBase = "https://github.com"
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("scope", "read:user")

	codeReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ghBase+"/login/device/code", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	codeReq.Header.Set("Accept", "application/json")
	codeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	codeResp, err := client.Do(codeReq)
	if err != nil {
		return "", fmt.Errorf("request GitHub device code: %w", err)
	}
	defer codeResp.Body.Close()

	var dc githubDeviceCodeResponse
	if err := json.NewDecoder(io.LimitReader(codeResp.Body, 64*1024)).Decode(&dc); err != nil {
		return "", fmt.Errorf("decode GitHub device code response: %w", err)
	}
	if codeResp.StatusCode != http.StatusOK || dc.DeviceCode == "" || dc.UserCode == "" {
		return "", fmt.Errorf("GitHub device flow initiation failed: %s %s", dc.Error, dc.ErrorDesc)
	}

	verifyURI := dc.VerificationURI
	if verifyURI == "" {
		verifyURI = "https://github.com/login/device"
	}
	fmt.Fprintf(out, "\nAuthenticate with GitHub:\n")
	fmt.Fprintf(out, "  1. Open:  %s\n", verifyURI)
	fmt.Fprintf(out, "  2. Enter: %s\n\n", dc.UserCode)
	fmt.Fprintf(out, "Waiting for authorization...\n")

	intervalSec := dc.Interval
	if intervalSec <= 0 {
		intervalSec = 5
	}
	expiresIn := dc.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 900
	}
	deadline := time.Now().Add(time.Duration(expiresIn) * time.Second)

	for {
		if time.Now().After(deadline) {
			return "", errors.New("GitHub device code expired before authorization completed")
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(time.Duration(intervalSec) * time.Second):
		}

		pollForm := url.Values{}
		pollForm.Set("client_id", clientID)
		pollForm.Set("device_code", dc.DeviceCode)
		pollForm.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

		pollReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ghBase+"/login/oauth/access_token", strings.NewReader(pollForm.Encode()))
		if err != nil {
			return "", err
		}
		pollReq.Header.Set("Accept", "application/json")
		pollReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		pollResp, err := client.Do(pollReq)
		if err != nil {
			return "", fmt.Errorf("poll GitHub device token: %w", err)
		}
		var tok githubDeviceTokenResponse
		decErr := json.NewDecoder(io.LimitReader(pollResp.Body, 64*1024)).Decode(&tok)
		pollResp.Body.Close()
		if decErr != nil {
			return "", fmt.Errorf("decode GitHub token response: %w", decErr)
		}

		if tok.AccessToken != "" {
			return tok.AccessToken, nil
		}

		switch tok.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			if tok.Interval > intervalSec {
				intervalSec = tok.Interval
			} else {
				intervalSec += 5
			}
		case "expired_token":
			return "", errors.New("GitHub device code expired")
		case "access_denied":
			return "", errors.New("GitHub authorization was denied by user")
		default:
			return "", fmt.Errorf("GitHub device flow error: %s (%s)", tok.Error, tok.ErrorDesc)
		}
	}
}

func resolveOfficialOrCustomProfile(profilePath string) (*profile.Profile, error) {
	if strings.TrimSpace(profilePath) != "" {
		return profile.LoadFile(profilePath)
	}
	if envProf := strings.TrimSpace(os.Getenv("ALT_PROFILE")); envProf != "" {
		return profile.LoadFile(envProf)
	}
	return profile.Official(), nil
}

func runLogin(args []string) error {
	if len(args) < 1 || args[0] != "github" {
		return fmt.Errorf("usage: alt login github [--registry <url>] [--client-id <github_client_id>] [--profile <path>] [--state-dir <dir>]")
	}

	flags := flag.NewFlagSet("login github", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	registryFlag := flags.String("registry", "", "ALT registry base URL (defaults to https://alt.goker.dev)")
	clientIDFlag := flags.String("client-id", "", "GitHub OAuth App Client ID for Device Flow")
	githubURLFlag := flags.String("github-url", "https://github.com", "GitHub base URL (used for testing)")
	githubTokenFlag := flags.String("github-token", "", "exchange an existing GitHub user token directly (non-interactive)")
	profileFlag := flags.String("profile", "", "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "directory for CLI credentials")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	prof, err := resolveOfficialOrCustomProfile(*profileFlag)
	if err != nil {
		return err
	}
	regURL, err := resolveRegistryBaseURL(*registryFlag)
	if err != nil {
		return err
	}
	stateDir, err := resolveStateBaseDir(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	ctx := context.Background()

	ghAccessToken := strings.TrimSpace(*githubTokenFlag)
	if ghAccessToken == "" {
		clientID := strings.TrimSpace(*clientIDFlag)
		if clientID == "" {
			clientID = strings.TrimSpace(os.Getenv("ALT_GITHUB_CLIENT_ID"))
		}
		if clientID == "" {
			clientID = strings.TrimSpace(os.Getenv("GITHUB_CLIENT_ID"))
		}
		ghAccessToken, err = runGitHubDeviceFlow(ctx, httpClient, *githubURLFlag, clientID, os.Stdout)
		if err != nil {
			return err
		}
	}

	var sessionResp cliSessionExchangeResponse
	_, err = registryJSONRequest(
		ctx,
		httpClient,
		http.MethodPost,
		regURL+"/api/cli/session",
		"",
		map[string]string{"githubAccessToken": ghAccessToken},
		&sessionResp,
	)
	if err != nil {
		return fmt.Errorf("exchange GitHub token for ALT CLI session: %w", err)
	}

	loc, err := writeSecret(stateDir, "cli-session.token", sessionResp.Token)
	if err != nil {
		return fmt.Errorf("save CLI session token: %w", err)
	}

	fmt.Printf("Authenticated with %s as @%s (%s)\n", regURL, sessionResp.Account.GitHubLogin, sessionResp.Account.ID)
	fmt.Printf("Session expires: %s (stored in %s)\n", sessionResp.ExpiresAt, loc)
	return nil
}

func runLogout(args []string) error {
	flags := flag.NewFlagSet("logout", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	registryFlag := flags.String("registry", "", "ALT registry base URL")
	profileFlag := flags.String("profile", "", "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "directory for CLI credentials")
	if err := flags.Parse(args); err != nil {
		return err
	}

	prof, err := resolveOfficialOrCustomProfile(*profileFlag)
	if err != nil {
		return err
	}
	regURL, err := resolveRegistryBaseURL(*registryFlag)
	if err != nil {
		return err
	}
	stateDir, err := resolveStateBaseDir(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	tok, err := readSecret(stateDir, "cli-session.token")
	if err == nil && tok != "" {
		httpClient := &http.Client{Timeout: 10 * time.Second}
		_, _ = registryJSONRequest(context.Background(), httpClient, http.MethodDelete, regURL+"/api/cli/session", tok, nil, nil)
	}
	deleteSecret(stateDir, "cli-session.token")
	fmt.Println("Logged out and removed local ALT CLI session token.")
	return nil
}

func runAccount(args []string) error {
	flags := flag.NewFlagSet("account", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	registryFlag := flags.String("registry", "", "ALT registry base URL")
	profileFlag := flags.String("profile", "", "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "directory for CLI credentials")
	if err := flags.Parse(args); err != nil {
		return err
	}

	prof, err := resolveOfficialOrCustomProfile(*profileFlag)
	if err != nil {
		return err
	}
	regURL, err := resolveRegistryBaseURL(*registryFlag)
	if err != nil {
		return err
	}
	stateDir, err := resolveStateBaseDir(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	tok, err := readSecret(stateDir, "cli-session.token")
	if err != nil {
		return errors.New("not logged in; run `alt login github` first")
	}

	httpClient := &http.Client{Timeout: 15 * time.Second}
	var acct accountResponse
	if _, err := registryJSONRequest(context.Background(), httpClient, http.MethodGet, regURL+"/api/account", tok, nil, &acct); err != nil {
		return err
	}

	ownerKeyDisplay := "(none — run `alt register <domain.alt>`)"
	if acct.Account.OwnerPublicKey != nil && *acct.Account.OwnerPublicKey != "" {
		ownerKeyDisplay = *acct.Account.OwnerPublicKey
	}

	fmt.Printf("Account:      @%s (%s)\n", acct.Account.GitHubLogin, acct.Account.ID)
	fmt.Printf("Network:      %s (.%s)\n", acct.Network.NetworkID, acct.Network.TLD)
	fmt.Printf("Owner Key:    %s\n", ownerKeyDisplay)
	if acct.Domain == nil {
		fmt.Printf("Domain:       (none allocated)\n")
	} else {
		cidStr := "-"
		if acct.Domain.ManifestCID != nil {
			cidStr = *acct.Domain.ManifestCID
		}
		fmt.Printf("Domain:       %s\n", acct.Domain.Name)
		fmt.Printf("Status:       %s (gen %d, seq %d)\n", acct.Domain.Status, acct.Domain.Generation, acct.Domain.Sequence)
		fmt.Printf("Publication:  %s (CID: %s)\n", acct.Domain.PublicationStatus, cidStr)
	}
	return nil
}

func runRegister(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: alt register <domain.alt> [--registry <url>] [--profile <path>] [--state-dir <dir>]")
	}
	rawDomain := args[0]

	flags := flag.NewFlagSet("register", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	registryFlag := flags.String("registry", "", "ALT registry base URL")
	profileFlag := flags.String("profile", "", "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "directory for CLI credentials and owner keys")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	prof, err := resolveOfficialOrCustomProfile(*profileFlag)
	if err != nil {
		return err
	}
	canonicalDomain, err := names.NormalizeDomain(rawDomain, prof.TLD)
	if err != nil {
		return err
	}
	regURL, err := resolveRegistryBaseURL(*registryFlag)
	if err != nil {
		return err
	}
	stateDir, err := resolveStateBaseDir(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	tok, err := readSecret(stateDir, "cli-session.token")
	if err != nil {
		return errors.New("not logged in; run `alt login github` first")
	}

	httpClient := &http.Client{Timeout: 20 * time.Second}
	ctx := context.Background()

	var acct accountResponse
	if _, err := registryJSONRequest(ctx, httpClient, http.MethodGet, regURL+"/api/account", tok, nil, &acct); err != nil {
		return err
	}
	if acct.Network.NetworkID != prof.NetworkID {
		return fmt.Errorf("registry networkId %q does not match local profile networkId %q", acct.Network.NetworkID, prof.NetworkID)
	}

	ownerPub, ownerPriv, err := loadOrCreateOwnerKey(stateDir, acct.Account.ID)
	if err != nil {
		return err
	}
	encodedOwnerPub := records.FormatPublicKey(ownerPub)

	// Step 1: If account has no bound ownerPublicKey yet, prove possession via single-use challenge (§4.3, §4.4).
	var latestDomain = acct.Domain
	if acct.Account.OwnerPublicKey == nil || *acct.Account.OwnerPublicKey == "" {
		var ch keyChallengeResponse
		if _, err := registryJSONRequest(ctx, httpClient, http.MethodPost, regURL+"/api/account/key/challenge", tok, map[string]any{}, &ch); err != nil {
			return fmt.Errorf("request owner-key challenge: %w", err)
		}
		if ch.NetworkID != prof.NetworkID || ch.AccountID != acct.Account.ID || ch.Purpose != records.KeyChallengePurposeBindOwnerKey {
			return fmt.Errorf("unexpected challenge metadata from registry (network=%q account=%q purpose=%q)", ch.NetworkID, ch.AccountID, ch.Purpose)
		}

		payload := &records.KeyChallengePayload{
			AccountID:      ch.AccountID,
			OwnerPublicKey: encodedOwnerPub,
			Nonce:          ch.Nonce,
			Purpose:        ch.Purpose,
			ExpiresAt:      ch.ExpiresAt,
		}
		sig, err := payload.Sign(prof.NetworkID, ownerPriv)
		if err != nil {
			return fmt.Errorf("sign owner-key challenge: %w", err)
		}

		var ver keyVerifyResponse
		if _, err := registryJSONRequest(ctx, httpClient, http.MethodPost, regURL+"/api/account/key/verify", tok, map[string]string{
			"ownerPublicKey": encodedOwnerPub,
			"nonce":          ch.Nonce,
			"expiresAt":      ch.ExpiresAt,
			"signature":      sig,
		}, &ver); err != nil {
			return fmt.Errorf("verify owner-key proof: %w", err)
		}
		latestDomain = ver.Domain
		fmt.Printf("Bound local Ed25519 owner key: %s\n", encodedOwnerPub)
	} else if *acct.Account.OwnerPublicKey != encodedOwnerPub {
		return fmt.Errorf("account already bound to owner key %s, which differs from local key %s", *acct.Account.OwnerPublicKey, encodedOwnerPub)
	}

	// Step 2: Allocate the domain if the user hasn't reserved it on the web yet.
	if latestDomain == nil {
		var regResp registerDomainResponse
		if _, err := registryJSONRequest(ctx, httpClient, http.MethodPost, regURL+"/api/domains", tok, map[string]string{
			"name": canonicalDomain,
		}, &regResp); err != nil {
			return err
		}
		latestDomain = &regResp.Domain
	} else if latestDomain.Name != canonicalDomain {
		return fmt.Errorf("account already owns %s (one-domain limit prevents registering %s)", latestDomain.Name, canonicalDomain)
	}

	if latestDomain.OwnershipRecord == nil {
		return fmt.Errorf("registry did not return a signed ownership certificate for %s (status: %s)", latestDomain.Name, latestDomain.Status)
	}

	// Step 3: Verify the authority-signed OwnershipCertificate locally against our pinned network profile!
	if len(prof.RegistryKeys) > 0 {
		if err := latestDomain.OwnershipRecord.VerifyForProfile(prof, time.Now().UTC()); err != nil {
			return fmt.Errorf("CRITICAL: ownership certificate returned by registry failed local profile signature verification: %w", err)
		}
	}

	fmt.Printf("Registered %s (status: %s, generation: %d)\n", latestDomain.Name, latestDomain.Status, latestDomain.Generation)
	fmt.Printf("Next: publish your HTTPS target with `alt publish %s --target https://your-origin.example`\n", latestDomain.Name)
	return nil
}

func runPublish(args []string) error {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: alt publish <domain.alt> --target <https://...> [--registry <url>] [--profile <path>] [--state-dir <dir>]")
	}
	rawDomain := args[0]

	flags := flag.NewFlagSet("publish", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	targetURLFlag := flags.String("target", "", "public HTTPS origin URL (e.g. https://my-app.vercel.app)")
	validDaysFlag := flags.Int("valid-days", 365, "target record validity window in days")
	registryFlag := flags.String("registry", "", "ALT registry base URL")
	profileFlag := flags.String("profile", "", "network profile YAML path")
	stateDirFlag := flags.String("state-dir", "", "directory for CLI credentials and owner keys")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	if strings.TrimSpace(*targetURLFlag) == "" {
		return fmt.Errorf("--target <https://...> is required (e.g. alt publish %s --target https://example.org)", rawDomain)
	}
	if *validDaysFlag < 1 || *validDaysFlag > 3650 {
		return fmt.Errorf("--valid-days must be between 1 and 3650")
	}

	prof, err := resolveOfficialOrCustomProfile(*profileFlag)
	if err != nil {
		return err
	}
	canonicalDomain, err := names.NormalizeDomain(rawDomain, prof.TLD)
	if err != nil {
		return err
	}
	regURL, err := resolveRegistryBaseURL(*registryFlag)
	if err != nil {
		return err
	}
	stateDir, err := resolveStateBaseDir(*stateDirFlag, prof.NetworkID)
	if err != nil {
		return err
	}

	tok, err := readSecret(stateDir, "cli-session.token")
	if err != nil {
		return errors.New("not logged in; run `alt login github` first")
	}

	httpClient := &http.Client{Timeout: 45 * time.Second}
	ctx := context.Background()

	var acct accountResponse
	if _, err := registryJSONRequest(ctx, httpClient, http.MethodGet, regURL+"/api/account", tok, nil, &acct); err != nil {
		return err
	}
	if acct.Domain == nil || acct.Domain.Name != canonicalDomain {
		return fmt.Errorf("domain %s is not allocated to @%s; run `alt register %s` first", canonicalDomain, acct.Account.GitHubLogin, canonicalDomain)
	}
	if acct.Domain.OwnershipRecord == nil {
		return fmt.Errorf("domain %s has no ownership certificate yet (status: %s); run `alt register %s` first", canonicalDomain, acct.Domain.Status, canonicalDomain)
	}

	cert := acct.Domain.OwnershipRecord
	now := time.Now().UTC().Truncate(time.Second)
	if len(prof.RegistryKeys) > 0 {
		if err := cert.VerifyForProfile(prof, now); err != nil {
			return fmt.Errorf("stored ownership certificate failed local profile verification: %w", err)
		}
	}

	ownerPub, ownerPriv, err := loadOrCreateOwnerKey(stateDir, acct.Account.ID)
	if err != nil {
		return err
	}
	if records.FormatPublicKey(ownerPub) != cert.OwnerPublicKey {
		return fmt.Errorf("local owner public key (%s) does not match certificate ownerPublicKey (%s)",
			records.FormatPublicKey(ownerPub), cert.OwnerPublicKey)
	}

	nextSeq := acct.Domain.Sequence + 1
	targetRec := &records.TargetRecord{
		Schema:              records.SchemaTargetV1,
		NetworkID:           prof.NetworkID,
		Domain:              canonicalDomain,
		OwnershipGeneration: cert.Generation,
		Sequence:            nextSeq,
		Mode:                records.TargetModeHTTPS,
		Target:              strings.TrimSpace(*targetURLFlag),
		IssuedAt:            now.Format(time.RFC3339),
		ExpiresAt:           now.Add(time.Duration(*validDaysFlag) * 24 * time.Hour).Format(time.RFC3339),
	}
	if err := targetRec.Sign(ownerPriv); err != nil {
		return fmt.Errorf("sign target record: %w", err)
	}
	if err := targetRec.Verify(cert, now); err != nil {
		return fmt.Errorf("local target record validation failed: %w", err)
	}

	var pubResp publishTargetResponse
	if _, err := registryJSONRequest(
		ctx,
		httpClient,
		http.MethodPut,
		regURL+"/api/domains/"+url.PathEscape(canonicalDomain)+"/target",
		tok,
		targetRec,
		&pubResp,
	); err != nil {
		return err
	}

	fmt.Printf("Published %s -> %s (sequence %d, status: %s)\n",
		pubResp.Domain.Name, targetRec.Target, pubResp.Domain.Sequence, pubResp.Domain.Status)
	if pubResp.Publication.ManifestCID != nil {
		fmt.Printf("Manifest CID: %s (%s)\n", *pubResp.Publication.ManifestCID, pubResp.Publication.Status)
	} else {
		fmt.Printf("Publication:  %s\n", pubResp.Publication.Status)
	}
	if pubResp.Publication.IPNSName != nil && *pubResp.Publication.IPNSName != "" {
		fmt.Printf("IPNS Root:    %s\n", *pubResp.Publication.IPNSName)
	}
	if pubResp.Publication.Error != nil && *pubResp.Publication.Error != "" {
		fmt.Printf("Warning:      IPFS/IPNS publication deferred: %s\n", *pubResp.Publication.Error)
	}
	return nil
}

