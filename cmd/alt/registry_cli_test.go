package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alt/pkg/profile"
	"alt/pkg/records"
	"gopkg.in/yaml.v3"
)

func TestCLILoginRegisterAccountPublishAndLogoutFlow(t *testing.T) {
	t.Setenv("ALT_DISABLE_KEYCHAIN", "1")

	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Mock GitHub Device Flow server
	var pollCount int
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/login/device/code":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code":      "dev_code_123",
				"user_code":        "ABCD-1234",
				"verification_uri": "https://github.com/login/device",
				"expires_in":       60,
				"interval":         1,
			})
		case "/login/oauth/access_token":
			pollCount++
			if pollCount == 1 {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": "authorization_pending",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "gho_mock_access_token_xyz",
				"token_type":   "bearer",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ghServer.Close()

	// Mock alt-registry API server enforcing token auth, challenge proof, ownership signing, and target verification
	const expectedCLIToken = "alt_cli_test_token_secret_123"
	const accountID = "gh:424242"
	var boundOwnerKey string
	var challengeNonce = "nonce_single_use_999"
	var challengeExpires = time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second).Format(time.RFC3339)
	var challengeConsumed bool
	var allocatedCert *records.OwnershipCertificate
	var storedTarget *records.TargetRecord
	var revoked bool

	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/api/cli/session" && r.Method == http.MethodPost {
			var body struct {
				GitHubAccessToken string `json:"githubAccessToken"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.GitHubAccessToken != "gho_mock_access_token_xyz" {
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "INVALID_GITHUB_TOKEN", "message": "bad gh token"}})
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token":     expectedCLIToken,
				"expiresAt": time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
				"account": map[string]any{
					"id":          accountID,
					"githubId":    "424242",
					"githubLogin": "goker",
				},
			})
			return
		}

		// Require CLI bearer token on all other endpoints
		if r.Header.Get("Authorization") != "Bearer "+expectedCLIToken || revoked {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "INVALID_CLI_TOKEN", "message": "unauthorized"}})
			return
		}

		switch {
		case r.URL.Path == "/api/cli/session" && r.Method == http.MethodDelete:
			revoked = true
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": true})

		case r.URL.Path == "/api/account" && r.Method == http.MethodGet:
			var dom any
			if allocatedCert != nil {
				seq := uint64(0)
				status := "pending_target"
				pubStatus := "not_ready"
				if storedTarget != nil {
					seq = storedTarget.Sequence
					status = "active"
					pubStatus = "published"
				}
				dom = map[string]any{
					"name":              allocatedCert.Domain,
					"label":             strings.TrimSuffix(allocatedCert.Domain, ".alt"),
					"kind":              "user",
					"status":            status,
					"generation":        allocatedCert.Generation,
					"sequence":          seq,
					"ownerPublicKey":    boundOwnerKey,
					"ownershipRecord":   allocatedCert,
					"targetRecord":      storedTarget,
					"publicationStatus": pubStatus,
					"manifestCid":       "bafkreidw3acn7s3vy6xmuyn2fui4sp3fxjfpnzm6m5mm6f76kueq3janra",
				}
			}
			var ownerKeyPtr any
			if boundOwnerKey != "" {
				ownerKeyPtr = boundOwnerKey
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account": map[string]any{
					"id":             accountID,
					"githubId":       "424242",
					"githubLogin":    "goker",
					"ownerPublicKey": ownerKeyPtr,
				},
				"domain": dom,
				"network": map[string]any{
					"networkId":           "alt-main-v1",
					"tld":                 "alt",
					"registrationEnabled": true,
				},
			})

		case r.URL.Path == "/api/account/key/challenge" && r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"networkId": "alt-main-v1",
				"accountId": accountID,
				"nonce":     challengeNonce,
				"purpose":   records.KeyChallengePurposeBindOwnerKey,
				"expiresAt": challengeExpires,
			})

		case r.URL.Path == "/api/account/key/verify" && r.Method == http.MethodPost:
			var body struct {
				OwnerPublicKey string `json:"ownerPublicKey"`
				Nonce          string `json:"nonce"`
				ExpiresAt      string `json:"expiresAt"`
				Signature      string `json:"signature"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if challengeConsumed || body.Nonce != challengeNonce || body.ExpiresAt != challengeExpires {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			payload := &records.KeyChallengePayload{
				AccountID:      accountID,
				OwnerPublicKey: body.OwnerPublicKey,
				Nonce:          body.Nonce,
				Purpose:        records.KeyChallengePurposeBindOwnerKey,
				ExpiresAt:      body.ExpiresAt,
			}
			if err := payload.Verify("alt-main-v1", body.Signature); err != nil {
				t.Errorf("challenge signature verify failed: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			challengeConsumed = true
			boundOwnerKey = body.OwnerPublicKey
			_ = json.NewEncoder(w).Encode(map[string]any{
				"account": map[string]any{
					"id":             accountID,
					"githubId":       "424242",
					"githubLogin":    "goker",
					"ownerPublicKey": boundOwnerKey,
				},
				"domain": nil,
			})

		case r.URL.Path == "/api/domains" && r.Method == http.MethodPost:
			var body struct {
				Name string `json:"name"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			now := time.Now().UTC().Truncate(time.Second)
			cert := &records.OwnershipCertificate{
				Schema:         records.SchemaOwnershipV1,
				NetworkID:      "alt-main-v1",
				Domain:         body.Name,
				AccountID:      accountID,
				OwnerPublicKey: boundOwnerKey,
				Generation:     1,
				IssuedAt:       now.Format(time.RFC3339),
				ExpiresAt:      now.Add(365 * 24 * time.Hour).Format(time.RFC3339),
				IssuerKeyID:    "registry-2026",
			}
			_ = cert.Sign(authPriv)
			allocatedCert = cert
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"domain": map[string]any{
					"name":              cert.Domain,
					"label":             "goker",
					"kind":              "user",
					"status":            "pending_target",
					"generation":        1,
					"sequence":          0,
					"ownerPublicKey":    boundOwnerKey,
					"ownershipRecord":   cert,
					"publicationStatus": "not_ready",
				},
			})

		case r.URL.Path == "/api/domains/goker.alt/target" && r.Method == http.MethodPut:
			rawBytes := make([]byte, 0)
			var tgt records.TargetRecord
			if err := json.NewDecoder(r.Body).Decode(&tgt); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = rawBytes
			if err := tgt.Verify(allocatedCert, time.Now().UTC()); err != nil {
				t.Errorf("server target verification failed: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			storedTarget = &tgt
			_ = json.NewEncoder(w).Encode(map[string]any{
				"domain": map[string]any{
					"name":              "goker.alt",
					"label":             "goker",
					"kind":              "user",
					"status":            "active",
					"generation":        1,
					"sequence":          tgt.Sequence,
					"ownerPublicKey":    boundOwnerKey,
					"ownershipRecord":   allocatedCert,
					"targetRecord":      tgt,
					"publicationStatus": "published",
					"manifestCid":       "bafkreidw3acn7s3vy6xmuyn2fui4sp3fxjfpnzm6m5mm6f76kueq3janra",
				},
				"publication": map[string]any{
					"status":      "published",
					"manifestCid": "bafkreidw3acn7s3vy6xmuyn2fui4sp3fxjfpnzm6m5mm6f76kueq3janra",
					"ipnsName":    profile.DefaultIPNSRoot,
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer regServer.Close()

	tmpDir := t.TempDir()
	prof := &profile.Profile{
		Version:   1,
		NetworkID: "alt-main-v1",
		TLD:       "alt",
		RegistryKeys: []profile.RegistryKey{
			{ID: "registry-2026", PublicKey: records.FormatPublicKey(authPub)},
		},
		ReservedNames: []string{"register"},
	}
	profYAML, _ := yaml.Marshal(prof)
	profPath := filepath.Join(tmpDir, "profile.yaml")
	if err := os.WriteFile(profPath, profYAML, 0o644); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(tmpDir, "state")

	// 1. alt login github (Device Flow polling -> token exchange -> 0600 secret storage)
	if err := runLogin([]string{
		"github",
		"--registry", regServer.URL,
		"--github-url", ghServer.URL,
		"--client-id", "Iv1.testclient",
		"--profile", profPath,
		"--state-dir", stateDir,
	}); err != nil {
		t.Fatalf("runLogin failed: %v", err)
	}

	tokStat, err := os.Stat(filepath.Join(stateDir, "cli-session.token"))
	if err != nil || tokStat.Mode().Perm() != 0o600 {
		t.Fatalf("expected cli-session.token with 0600 permissions, got stat=%v err=%v", tokStat, err)
	}

	// 2. alt register goker.alt (generates 0600 Ed25519 owner key, signs challenge, verifies authority OwnershipCertificate)
	if err := runRegister([]string{
		"goker.alt",
		"--registry", regServer.URL,
		"--profile", profPath,
		"--state-dir", stateDir,
	}); err != nil {
		t.Fatalf("runRegister failed: %v", err)
	}

	ownerKeyStat, err := os.Stat(filepath.Join(stateDir, "owner-gh_424242.key"))
	if err != nil || ownerKeyStat.Mode().Perm() != 0o600 {
		t.Fatalf("expected owner key file with 0600 permissions, got stat=%v err=%v", ownerKeyStat, err)
	}

	// 3. alt publish goker.alt --target https://alt.goker.dev
	if err := runPublish([]string{
		"goker.alt",
		"--target", "https://alt.goker.dev",
		"--registry", regServer.URL,
		"--profile", profPath,
		"--state-dir", stateDir,
	}); err != nil {
		t.Fatalf("runPublish failed: %v", err)
	}
	if storedTarget == nil || storedTarget.Sequence != 1 || storedTarget.Target != "https://alt.goker.dev" {
		t.Fatalf("unexpected storedTarget after publish: %+v", storedTarget)
	}

	// 4. alt account
	if err := runAccount([]string{
		"--registry", regServer.URL,
		"--profile", profPath,
		"--state-dir", stateDir,
	}); err != nil {
		t.Fatalf("runAccount failed: %v", err)
	}

	// 5. alt logout (revokes server session + deletes local token)
	if err := runLogout([]string{
		"--registry", regServer.URL,
		"--profile", profPath,
		"--state-dir", stateDir,
	}); err != nil {
		t.Fatalf("runLogout failed: %v", err)
	}
	if !revoked {
		t.Fatalf("expected server CLI session to be revoked on logout")
	}
}

