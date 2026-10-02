// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
	"github.com/falcosecurity/falcosidekick/types"
)

// tokenProvider interface for getting tokens
type tokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// isLoopbackHost checks if a hostname is a loopback address
func isLoopbackHost(host string) bool {
	// Check for localhost
	if host == "localhost" {
		return true
	}

	// Check for IP address
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// clientCredentialsProvider handles OAuth2 client credentials flow
type clientCredentialsProvider struct {
	config *clientcredentials.Config
	source oauth2.TokenSource
}

// fileTokenProvider handles reading tokens from a file
type fileTokenProvider struct {
	filePath string
	mu       sync.RWMutex
	token    string
	mtime    time.Time
	lastStat time.Time
}

// newClientCredentialsProvider creates a new OAuth2 client credentials provider
func newClientCredentialsProvider(cfg types.WebUIOAuth2Config, outputType string) (*clientCredentialsProvider, error) {
	// Validate required fields
	if cfg.TokenURL == "" {
		return nil, errors.New("oauth2: tokenurl is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("oauth2: clientid is required")
	}

	// Validate tokenurl uses HTTPS unless loopback
	parsedTokenURL, err := url.Parse(cfg.TokenURL)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to parse tokenurl: %w", err)
	}
	if parsedTokenURL.Scheme != "https" {
		host := parsedTokenURL.Hostname()
		if host == "" || !isLoopbackHost(host) {
			return nil, errors.New("oauth2: tokenurl must use https unless the host is a loopback address (localhost, 127.0.0.1, ::1)")
		}
	}

	// Resolve client secret
	clientSecret := cfg.ClientSecret
	if cfg.ClientSecretFile != "" {
		data, err := os.ReadFile(cfg.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to read clientsecretfile: %w", err)
		}
		clientSecret = strings.TrimSpace(string(data))
	}

	if clientSecret == "" {
		return nil, errors.New("oauth2: clientsecret or clientsecretfile is required")
	}

	// Create TLS config for token endpoint
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Set up root CAs
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	tlsConfig.RootCAs = pool

	// Add custom CA if provided
	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("oauth2: failed to read cafile: %w", err)
		}
		if len(caCert) > 0 && !tlsConfig.RootCAs.AppendCertsFromPEM(caCert) {
			return nil, errors.New("oauth2: failed to append CA certificate")
		}
	}

	// Parse scopes (accept both comma and space-separated)
	var scopes []string
	if cfg.Scopes != "" {
		// Split on both commas and whitespace, drop empty strings
		rawScopes := strings.FieldsFunc(cfg.Scopes, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
		})
		scopes = rawScopes
	}

	// Create HTTP client with TLS config and timeout
	// Use DefaultTransport clone to preserve proxy settings, dial timeouts, HTTP/2, etc.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	tokenHTTPClient := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}

	// Build OAuth2 config
	oauth2Config := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: clientSecret,
		TokenURL:     cfg.TokenURL,
		Scopes:       scopes,
	}

	// Add audience and resource parameters if provided
	if cfg.Audience != "" {
		oauth2Config.EndpointParams = make(map[string][]string)
		oauth2Config.EndpointParams.Set("audience", cfg.Audience)
		if cfg.ResourceIndicator {
			oauth2Config.EndpointParams.Set("resource", cfg.Audience)
		}
	}

	// Create token source (clientcredentials.Config.TokenSource already handles caching)
	source := oauth2Config.TokenSource(context.WithValue(context.Background(), oauth2.HTTPClient, tokenHTTPClient))

	return &clientCredentialsProvider{
		config: oauth2Config,
		source: source,
	}, nil
}

// Token returns the current OAuth2 token
func (p *clientCredentialsProvider) Token(ctx context.Context) (string, error) {
	token, err := p.source.Token()
	if err != nil {
		return "", fmt.Errorf("oauth2: failed to get token: %w", err)
	}
	return token.AccessToken, nil
}

// newFileTokenProvider creates a new file-based token provider
func newFileTokenProvider(filePath string) (*fileTokenProvider, error) {
	if filePath == "" {
		return nil, errors.New("tokenfile: path is required")
	}

	provider := &fileTokenProvider{
		filePath: filePath,
		lastStat: time.Now(),
	}

	// Read initial token
	if err := provider.refresh(); err != nil {
		return nil, err
	}

	return provider, nil
}

// refresh reads the token from file if it has been updated
func (p *fileTokenProvider) refresh() error {
	// Stat at most every 30s
	now := time.Now()
	p.mu.RLock()
	lastStat := p.lastStat
	oldMTime := p.mtime
	p.mu.RUnlock()

	// Check 30s throttle only if we've already read the file
	if !oldMTime.IsZero() && now.Sub(lastStat) < 30*time.Second {
		return nil
	}

	info, err := os.Stat(p.filePath)
	if err != nil {
		return fmt.Errorf("tokenfile: failed to stat file: %w", err)
	}

	newMTime := info.ModTime()

	// Only read if modified (including restored or older files) or not yet read
	if !oldMTime.IsZero() && newMTime.Equal(oldMTime) {
		p.mu.Lock()
		p.lastStat = now
		p.mu.Unlock()
		return nil
	}

	// Read new token
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return fmt.Errorf("tokenfile: failed to read file: %w", err)
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return errors.New("tokenfile: file is empty")
	}

	p.mu.Lock()
	p.token = token
	p.mtime = newMTime
	p.lastStat = now
	p.mu.Unlock()

	return nil
}

// Token returns the current token from file
func (p *fileTokenProvider) Token(ctx context.Context) (string, error) {
	if err := p.refresh(); err != nil {
		return "", err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.token == "" {
		return "", errors.New("tokenfile: no token available")
	}

	return p.token, nil
}

// ValidateWebUIAuth validates OAuth2 and TokenFile configuration
func ValidateWebUIAuth(config types.WebUIOutputConfig, outputType string) (tokenProvider, error) {
	hasOAuth2 := config.OAuth2.TokenURL != ""
	hasTokenFile := config.TokenFile != ""

	// Check for conflicting configuration
	if hasOAuth2 && hasTokenFile {
		return nil, errors.New("webui: cannot configure both oauth2 and tokenfile")
	}

	// If neither is configured, return nil (no auth)
	if !hasOAuth2 && !hasTokenFile {
		return nil, nil
	}

	// Configure OAuth2
	if hasOAuth2 {
		provider, err := newClientCredentialsProvider(config.OAuth2, outputType)
		if err != nil {
			return nil, fmt.Errorf("webui: %w", err)
		}
		return provider, nil
	}

	// Configure token file
	if hasTokenFile {
		provider, err := newFileTokenProvider(config.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("webui: %w", err)
		}
		return provider, nil
	}

	return nil, nil
}

// ValidateWebUIAuthURL validates that if a token source is configured, the UI URL uses TLS (unless loopback)
func ValidateWebUIAuthURL(uiURL string, hasAuth bool) error {
	if !hasAuth {
		return nil
	}

	if !strings.HasPrefix(uiURL, "https://") {
		// Parse URL to extract hostname securely
		parsedURL, err := url.Parse(uiURL)
		if err == nil && isLoopbackHost(parsedURL.Hostname()) {
			return nil
		}
		// Log warning for plaintext HTTP (but don't block, for service mesh deployments)
		utils.Log(utils.WarningLvl, "WebUI", "bearer token sent over plaintext HTTP; use TLS or a service mesh")
	}

	return nil
}
