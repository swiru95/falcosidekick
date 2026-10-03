// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
)

// certReloader holds certificate file paths and cached certificate for hot-reloading.
type certReloader struct {
	certFile      string
	keyFile       string
	interval      time.Duration
	cachedCert    *tls.Certificate
	lastMtimeCert time.Time
	lastMtimeKey  time.Time
	lastCheckTime time.Time
	mu            sync.Mutex
}

// newCertReloader creates a new certificate reloader and loads the initial certificate.
// It returns an error if the initial load fails.
func newCertReloader(certFile, keyFile string, interval time.Duration) (*certReloader, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load initial certificate: %w", err)
	}

	r := &certReloader{
		certFile:   certFile,
		keyFile:    keyFile,
		interval:   interval,
		cachedCert: &cert,
	}

	// Set initial mtimes
	certInfo, _ := os.Stat(certFile)
	keyInfo, _ := os.Stat(keyFile)
	if certInfo != nil {
		r.lastMtimeCert = certInfo.ModTime()
	}
	if keyInfo != nil {
		r.lastMtimeKey = keyInfo.ModTime()
	}
	r.lastCheckTime = time.Now()

	return r, nil
}

// GetCertificate implements the tls.Config.GetCertificate callback.
// It checks if certificate files have changed (at most once per interval) and reloads if needed.
func (r *certReloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if enough time has passed since last check
	if time.Since(r.lastCheckTime) < r.interval {
		return r.cachedCert, nil
	}

	r.lastCheckTime = time.Now()

	// Stat both files to check for changes
	certInfo, certErr := os.Stat(r.certFile)
	keyInfo, keyErr := os.Stat(r.keyFile)

	// Determine if files have changed
	certChanged := false
	keyChanged := false

	if certErr == nil && certInfo != nil {
		if r.lastMtimeCert != certInfo.ModTime() {
			certChanged = true
		}
	}

	if keyErr == nil && keyInfo != nil {
		if r.lastMtimeKey != keyInfo.ModTime() {
			keyChanged = true
		}
	}

	// If nothing changed, return cached cert
	if !certChanged && !keyChanged {
		return r.cachedCert, nil
	}

	// Try to load new certificate
	newCert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		// Keep previous cert and log error
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("failed to reload TLS certificate: %v", err))
		return r.cachedCert, nil
	}

	// Update cached cert and mtimes
	r.cachedCert = &newCert
	if certInfo != nil {
		r.lastMtimeCert = certInfo.ModTime()
	}
	if keyInfo != nil {
		r.lastMtimeKey = keyInfo.ModTime()
	}

	utils.Log(utils.InfoLvl, "", "TLS server certificate reloaded")

	return r.cachedCert, nil
}

// allowedSANVerifier returns a function that verifies the client certificate's SAN
// against an allow-list. If the allow-list is empty, all certificates are accepted.
func allowedSANVerifier(allowed []string) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		// If no restrictions, accept any certificate signed by the CA
		if len(allowed) == 0 {
			return nil
		}

		// Check for peer certificate
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("no peer certificate provided")
		}

		peerCert := cs.PeerCertificates[0]

		// Build set of presented SANs for error message
		var presentedSANs []string

		// Check DNS names
		for _, dnsName := range peerCert.DNSNames {
			presentedSANs = append(presentedSANs, dnsName)
			for _, allowed := range allowed {
				if dnsName == allowed {
					return nil
				}
			}
		}

		// Check URIs
		for _, uri := range peerCert.URIs {
			uriStr := uri.String()
			presentedSANs = append(presentedSANs, uriStr)
			for _, allowed := range allowed {
				if uriStr == allowed {
					return nil
				}
			}
		}

		// Check CommonName
		cn := peerCert.Subject.CommonName
		if cn != "" {
			presentedSANs = append(presentedSANs, cn)
			for _, allowed := range allowed {
				if cn == allowed {
					return nil
				}
			}
		}

		// No match found
		return fmt.Errorf("client certificate SAN not in allow-list; presented SANs: %v", presentedSANs)
	}
}
