// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/falcosecurity/falcosidekick/internal/pkg/utils"
)

// certReloader holds certificate file paths and cached certificate for hot-reloading.
type certReloader struct {
	certFile        string
	keyFile         string
	interval        time.Duration
	cachedCert      *tls.Certificate
	lastContentHash [sha256.Size]byte
	lastCheckTime   time.Time
	mu              sync.Mutex
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

	// Compute initial content hash
	if err := r.updateContentHash(); err != nil {
		return nil, fmt.Errorf("failed to compute initial certificate hash: %w", err)
	}
	r.lastCheckTime = time.Now()

	return r, nil
}

// updateContentHash reads both cert and key files and computes their SHA-256 hash.
func (r *certReloader) updateContentHash() error {
	certData, err := os.ReadFile(r.certFile)
	if err != nil {
		return err
	}
	keyData, err := os.ReadFile(r.keyFile)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write(certData)
	h.Write(keyData)
	copy(r.lastContentHash[:], h.Sum(nil))
	return nil
}

// GetCertificate implements the tls.Config.GetCertificate callback.
// It checks if certificate files have changed by content hash (at most once per interval) and reloads if needed.
func (r *certReloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if enough time has passed since last check
	if time.Since(r.lastCheckTime) < r.interval {
		return r.cachedCert, nil
	}

	r.lastCheckTime = time.Now()

	// Read both files and compute hash
	certData, err := os.ReadFile(r.certFile)
	if err != nil {
		// Keep previous cert and log error
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("failed to read certificate file: %v", err))
		return r.cachedCert, nil
	}
	keyData, err := os.ReadFile(r.keyFile)
	if err != nil {
		// Keep previous cert and log error
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("failed to read key file: %v", err))
		return r.cachedCert, nil
	}

	h := sha256.New()
	h.Write(certData)
	h.Write(keyData)
	var currentHash [sha256.Size]byte
	copy(currentHash[:], h.Sum(nil))

	// If content hasn't changed, return cached cert
	if currentHash == r.lastContentHash {
		return r.cachedCert, nil
	}

	// Try to load new certificate from the bytes just read
	newCert, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		// Keep previous cert and log error
		utils.Log(utils.ErrorLvl, "", fmt.Sprintf("failed to reload TLS certificate: %v", err))
		return r.cachedCert, nil
	}

	// Chain-shrink guard: check if new chain has fewer certificates
	if len(newCert.Certificate) < len(r.cachedCert.Certificate) {
		utils.Log(utils.WarningLvl, "", fmt.Sprintf("TLS certificate reload skipped: new chain has %d certs, current has %d (partial write?)", len(newCert.Certificate), len(r.cachedCert.Certificate)))
		return r.cachedCert, nil
	}

	// Update cached cert and content hash
	r.cachedCert = &newCert
	copy(r.lastContentHash[:], currentHash[:])

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
