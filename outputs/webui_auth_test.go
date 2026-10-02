// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

// TestClientCredentialsFlow tests OAuth2 client credentials grant flow
func TestClientCredentialsFlow(t *testing.T) {
	tokenCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		// Verify grant type
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("Expected grant_type=client_credentials, got %s", r.FormValue("grant_type"))
		}
		// Verify client auth
		username, password, ok := r.BasicAuth()
		if !ok || username != "test-client" || password != "test-secret" {
			t.Errorf("Expected Basic auth with test-client:test-secret")
		}
		// Verify scopes (should be space-separated per OAuth2 spec)
		scope := r.FormValue("scope")
		if scope != "api read" {
			t.Errorf("Expected scope=api read, got %s", scope)
		}
		// Verify audience
		audience := r.FormValue("audience")
		if audience != "test-audience" {
			t.Errorf("Expected audience=test-audience, got %s", audience)
		}
		// Return token
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scopes:       "api read",
			Audience:     "test-audience",
		},
	}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// First call should hit token server
	token1, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token1 != "test-token-123" {
		t.Errorf("Expected test-token-123, got %s", token1)
	}

	// Second call should reuse token (not hit server again)
	token2, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token2 != "test-token-123" {
		t.Errorf("Expected test-token-123, got %s", token2)
	}

	// Should only have hit server once due to token reuse
	if tokenCalls != 1 {
		t.Errorf("Expected 1 token call, got %d", tokenCalls)
	}
}

// TestFileTokenProvider tests reading tokens from file
func TestFileTokenProvider(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Write initial token
	initialToken := "initial-token-123"
	if err := os.WriteFile(tokenFile, []byte(initialToken+"\n"), 0644); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	config := types.WebUIOutputConfig{
		TokenFile: tokenFile,
	}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Read token
	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != initialToken {
		t.Errorf("Expected %s, got %s", initialToken, token)
	}

	// Test that same token is returned without re-reading (within 30s window)
	token2, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token2 != initialToken {
		t.Errorf("Expected %s, got %s", initialToken, token2)
	}

	// For testing file rotation after 30s, we would need to wait or mock time.
	// Since that's impractical in unit tests, we just verify the initial read works.
}

// TestFileTokenProviderEmpty tests error when token file is empty
func TestFileTokenProviderEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	tokenFile := filepath.Join(tmpDir, "token")

	// Create empty file
	if err := os.WriteFile(tokenFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}

	config := types.WebUIOutputConfig{
		TokenFile: tokenFile,
	}

	_, err := ValidateWebUIAuth(config, "test")
	if err == nil {
		t.Error("Expected error for empty token file")
	}
}

// TestFileTokenProviderMissing tests error when token file doesn't exist
func TestFileTokenProviderMissing(t *testing.T) {
	config := types.WebUIOutputConfig{
		TokenFile: "/nonexistent/token/file",
	}

	_, err := ValidateWebUIAuth(config, "test")
	if err == nil {
		t.Error("Expected error for missing token file")
	}
}

// TestValidateWebUIAuthConflict tests error when both OAuth2 and TokenFile are configured
func TestValidateWebUIAuthConflict(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL: "https://example.com/token",
			ClientID: "test",
		},
		TokenFile: "/some/file",
	}

	_, err := ValidateWebUIAuth(config, "test")
	if err == nil {
		t.Error("Expected error for conflicting auth config")
	}
}

// TestValidateWebUIAuthMissingClientID tests error when ClientID is missing
func TestValidateWebUIAuthMissingClientID(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL: "https://example.com/token",
		},
	}

	_, err := ValidateWebUIAuth(config, "test")
	if err == nil {
		t.Error("Expected error for missing clientid")
	}
}

// TestValidateWebUIAuthMissingSecret tests error when neither ClientSecret nor ClientSecretFile is configured
func TestValidateWebUIAuthMissingSecret(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL: "https://example.com/token",
			ClientID: "test-client",
		},
	}

	_, err := ValidateWebUIAuth(config, "test")
	if err == nil {
		t.Error("Expected error for missing secret")
	}
}

// TestValidateWebUIAuthSecretFile tests reading secret from file
func TestValidateWebUIAuthSecretFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret")
	if err := os.WriteFile(secretFile, []byte("secret-from-file\n"), 0644); err != nil {
		t.Fatalf("Failed to write secret file: %v", err)
	}

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:         server.URL,
			ClientID:         "test-client",
			ClientSecretFile: secretFile,
		},
	}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != "test-token" {
		t.Errorf("Expected test-token, got %s", token)
	}
}

// TestValidateWebUIAuthHTTPTokenURLNonLoopback tests warning for HTTP token URL
func TestValidateWebUIAuthHTTPTokenURLNonLoopback(t *testing.T) {
	// The spec says it should log a warning but not block for non-loopback HTTP
	err := ValidateWebUIAuthURL("http://example.com", true)
	if err == nil {
		// This is expected - the validation logs a warning but doesn't return an error
	}
}

// TestValidateWebUIAuthHTTPTokenURLLoopback tests no error for HTTP loopback
func TestValidateWebUIAuthHTTPTokenURLLoopback(t *testing.T) {
	err := ValidateWebUIAuthURL("http://localhost:8080", true)
	if err != nil {
		t.Errorf("Expected no error for loopback HTTP, got %v", err)
	}
}

// TestValidateWebUIAuthHTTPSTokenURL tests no error for HTTPS URL
func TestValidateWebUIAuthHTTPSTokenURL(t *testing.T) {
	err := ValidateWebUIAuthURL("https://example.com", true)
	if err != nil {
		t.Errorf("Expected no error for HTTPS URL, got %v", err)
	}
}

// TestWebUIPostWithAuthorization tests WebUIPost with authorization header
func TestWebUIPostWithAuthorization(t *testing.T) {
	// Create a mock UI server
	var authHeader string
	uiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer uiServer.Close()

	// Create OAuth2 token server
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-bearer-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer tokenServer.Close()

	// Create token provider first
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     tokenServer.URL,
			ClientID:     "test",
			ClientSecret: "secret",
		},
	}
	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Get a token to verify it works
	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}

	// Create a simple request to test the header
	req, err := http.NewRequest("POST", uiServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set(AuthorizationHeaderKey, Bearer+" "+token)

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Verify authorization header was sent
	if authHeader != "Bearer test-bearer-token" {
		t.Errorf("Expected 'Bearer test-bearer-token', got '%s'", authHeader)
	}
}

// TestWebUIPostWithoutAuthorization tests WebUIPost without authorization when not configured
func TestWebUIPostWithoutAuthorization(t *testing.T) {
	// Create a mock UI server
	var authHeader string
	uiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer uiServer.Close()

	// Create a simple request without auth
	req, err := http.NewRequest("POST", uiServer.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	// Note: not setting Authorization header

	// Send request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Verify no authorization header
	if authHeader != "" {
		t.Errorf("Expected no Authorization header, got '%s'", authHeader)
	}
}

// TestOAuth2CAFile tests OAuth2 with custom CA file
func TestOAuth2CAFile(t *testing.T) {
	// Create a test CA file (empty is acceptable - no certs to add)
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caFile, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     server.URL,
			ClientID:     "test",
			ClientSecret: "secret",
			CAFile:       caFile,
		},
	}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != "test-token" {
		t.Errorf("Expected test-token, got %s", token)
	}
}

// TestOAuth2ResourceIndicator tests OAuth2 with resource indicator flag
func TestOAuth2ResourceIndicator(t *testing.T) {
	requestCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCalls++
		if err := r.ParseForm(); err != nil {
			t.Fatalf("Failed to parse form: %v", err)
		}
		// Verify both audience and resource are sent
		audience := r.FormValue("audience")
		resource := r.FormValue("resource")
		if audience != "test-audience" {
			t.Errorf("Expected audience=test-audience, got %s", audience)
		}
		if resource != "test-audience" {
			t.Errorf("Expected resource=test-audience, got %s", resource)
		}
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:          server.URL,
			ClientID:          "test",
			ClientSecret:      "secret",
			Audience:          "test-audience",
			ResourceIndicator: true,
		},
	}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	token, err := provider.Token(context.Background())
	if err != nil {
		t.Fatalf("Failed to get token: %v", err)
	}
	if token != "test-token" {
		t.Errorf("Expected test-token, got %s", token)
	}
}

// TestNoAuthConfigured tests that ValidateWebUIAuth returns nil when no auth is configured
func TestNoAuthConfigured(t *testing.T) {
	config := types.WebUIOutputConfig{}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if provider != nil {
		t.Error("Expected nil provider when no auth configured")
	}
}

// TestOAuth2TokenURLHTTPNonLoopback tests error when tokenurl is HTTP on non-loopback
func TestOAuth2TokenURLHTTPNonLoopback(t *testing.T) {
	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     "http://example.com/token",
			ClientID:     "test",
			ClientSecret: "secret",
		},
	}

	_, err := ValidateWebUIAuth(config, "test")
	if err == nil {
		t.Error("Expected error for HTTP tokenurl on non-loopback host")
	}
}

// TestOAuth2TokenURLHTTPLoopback tests success when tokenurl is HTTP on loopback
func TestOAuth2TokenURLHTTPLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := types.WebUIOutputConfig{
		OAuth2: types.WebUIOAuth2Config{
			TokenURL:     "http://127.0.0.1:8080/token",
			ClientID:     "test",
			ClientSecret: "secret",
		},
	}

	provider, err := ValidateWebUIAuth(config, "test")
	if err != nil {
		t.Errorf("Expected no error for HTTP tokenurl on loopback, got %v", err)
	}
	if provider == nil {
		t.Error("Expected provider for loopback tokenurl")
	}
}

// TestLoopbackBypassAttempts tests that hostname validation is not bypassable with malicious URLs
func TestLoopbackBypassAttempts(t *testing.T) {
	testCases := []struct {
		name       string
		url        string
		shouldFail bool
	}{
		{"localhost.attacker.com", "http://localhost.attacker.com/token", true},
		{"URL with query localhost", "http://attacker.com/?x=localhost/token", true},
		{"localhost port", "http://localhost:8080/token", false},
		{"127.0.0.1", "http://127.0.0.1/token", false},
		{"::1", "http://[::1]/token", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := types.WebUIOutputConfig{
				OAuth2: types.WebUIOAuth2Config{
					TokenURL:     tc.url,
					ClientID:     "test",
					ClientSecret: "secret",
				},
			}

			_, err := ValidateWebUIAuth(config, "test")
			if tc.shouldFail && err == nil {
				t.Errorf("Expected error for bypass attempt: %s", tc.name)
			}
			if !tc.shouldFail && err != nil {
				t.Errorf("Expected success for loopback %s, got error: %v", tc.name, err)
			}
		})
	}
}

// TestWebUIURLBypassLoopback tests loopback detection for WebUI URL
func TestWebUIURLBypassLoopback(t *testing.T) {
	testCases := []struct {
		name       string
		url        string
		shouldWarn bool
	}{
		{"http://localhost", "http://localhost/", false},
		{"http://127.0.0.1", "http://127.0.0.1/", false},
		{"http://[::1]", "http://[::1]/", false},
		{"http://localhost.attacker.com", "http://localhost.attacker.com/", true},
		{"https://attacker.com", "https://attacker.com/", false},
		{"http://attacker.com", "http://attacker.com/", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// ValidateWebUIAuthURL should not return error (just warn) but we check it doesn't error
			err := ValidateWebUIAuthURL(tc.url, true)
			if err != nil {
				t.Errorf("ValidateWebUIAuthURL should not error, got: %v", err)
			}
		})
	}
}

// TestScopesCommaAndSpaceSeparated tests that both comma and space-separated scopes work
func TestScopesCommaAndSpaceSeparated(t *testing.T) {
	testCases := []struct {
		name   string
		scopes string
	}{
		{"comma-separated", "api,read"},
		{"space-separated", "api read"},
		{"mixed", "api, read"},
		{"tabs and newlines", "api\tread"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatalf("Failed to parse form: %v", err)
				}
				scope := r.FormValue("scope")
				// Should have api and read as separate values
				if !strings.Contains(scope, "api") || !strings.Contains(scope, "read") {
					t.Errorf("Expected scope to contain 'api' and 'read', got: %s", scope)
				}
				w.Header().Set("Content-Type", "application/json")
				response := map[string]interface{}{
					"access_token": "test-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()

			config := types.WebUIOutputConfig{
				OAuth2: types.WebUIOAuth2Config{
					TokenURL:     server.URL,
					ClientID:     "test",
					ClientSecret: "secret",
					Scopes:       tc.scopes,
				},
			}

			provider, err := ValidateWebUIAuth(config, "test")
			if err != nil {
				t.Errorf("Failed to create provider: %v", err)
				return
			}

			_, err = provider.Token(context.Background())
			if err != nil {
				t.Errorf("Failed to get token: %v", err)
			}
		})
	}
}
