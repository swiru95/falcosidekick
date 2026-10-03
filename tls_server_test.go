// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	certBlockType       = "CERTIFICATE"
	privateKeyBlockType = "PRIVATE KEY"
	testLocalName       = "test.local"
	testLocalName2      = "test2.local"
)

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(commonName string, dnsNames []string) (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: certBlockType, Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: privateKeyBlockType, Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateRootCA generates a root CA certificate for testing.
func generateRootCA() (certPEM, keyPEM []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: certBlockType, Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: privateKeyBlockType, Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// generateSignedCertificate generates a certificate signed by a CA.
func generateSignedCertificate(commonName string, dnsNames []string, caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte, err error) {
	// Parse CA certificate and key
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	caKeyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:    dnsNames,
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &privateKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: certBlockType, Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{Type: privateKeyBlockType, Bytes: keyDER})

	return certPEM, keyPEM, nil
}

// TestCertReloaderReloadsOnChange tests that the reloader detects and loads new certificates.
func TestCertReloaderReloadsOnChange(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader with 0 interval for testing
	reloader, err := newCertReloader(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate
	initialCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get initial certificate: %v", err)
	}

	// Wait a moment to ensure mtime will be different
	time.Sleep(100 * time.Millisecond)

	// Generate new certificate
	newCertPEM, newKeyPEM, err := generateTestCertificate(testLocalName2, []string{testLocalName2})
	if err != nil {
		t.Fatalf("failed to generate new certificate: %v", err)
	}

	if err := os.WriteFile(certFile, newCertPEM, 0600); err != nil {
		t.Fatalf("failed to write new cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, newKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write new key file: %v", err)
	}

	// Explicitly update mtime to trigger reload
	now := time.Now()
	os.Chtimes(certFile, now, now)
	os.Chtimes(keyFile, now, now)

	// Get certificate again - should get the new one
	newCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get new certificate: %v", err)
	}

	// Verify certificates are different
	if initialCert == newCert {
		t.Error("expected different certificate after reload")
	}
}

// TestCertReloaderKeepsPreviousOnError tests that reloader keeps serving old cert on errors.
func TestCertReloaderKeepsPreviousOnError(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader with 0 interval for testing
	reloader, err := newCertReloader(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate
	initialCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get initial certificate: %v", err)
	}

	// Wait a moment
	time.Sleep(100 * time.Millisecond)

	// Write corrupt data to cert file
	if err := os.WriteFile(certFile, []byte("corrupt"), 0600); err != nil {
		t.Fatalf("failed to write corrupt cert file: %v", err)
	}

	// Update mtime to trigger reload
	now := time.Now()
	os.Chtimes(certFile, now, now)

	// Get certificate again - should still get the old one
	cert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	// Should return the original cert
	if initialCert != cert {
		t.Error("expected same certificate after failed reload")
	}
}

// TestCertReloaderContentChangeIdenticalMtime tests that content changes are detected even with identical mtime.
func TestCertReloaderContentChangeIdenticalMtime(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate
	certPEM, keyPEM, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader with 0 interval for testing
	reloader, err := newCertReloader(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate
	initialCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get initial certificate: %v", err)
	}

	// Get file info to preserve mtime
	fileInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatalf("failed to stat cert file: %v", err)
	}
	originalMtime := fileInfo.ModTime()

	// Generate new certificate
	newCertPEM, newKeyPEM, err := generateTestCertificate(testLocalName2, []string{testLocalName2})
	if err != nil {
		t.Fatalf("failed to generate new certificate: %v", err)
	}

	// Write new cert with same mtime
	if err := os.WriteFile(certFile, newCertPEM, 0600); err != nil {
		t.Fatalf("failed to write new cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, newKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write new key file: %v", err)
	}

	// Restore original mtime to test content-based detection
	os.Chtimes(certFile, originalMtime, originalMtime)
	os.Chtimes(keyFile, originalMtime, originalMtime)

	// Get certificate again - should get the new one despite identical mtime
	newCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get new certificate: %v", err)
	}

	// Verify certificates are different
	if initialCert == newCert {
		t.Error("expected different certificate after content change with identical mtime")
	}
}

// TestCertReloaderChainShrinkGuard tests that shorter certificate chains are not swapped in.
func TestCertReloaderChainShrinkGuard(t *testing.T) {
	tmpDir := t.TempDir()
	certFile := filepath.Join(tmpDir, "cert.pem")
	keyFile := filepath.Join(tmpDir, "key.pem")

	// Generate initial certificate with intermediate
	caCertPEM, caKeyPEM, err := generateRootCA()
	if err != nil {
		t.Fatalf("failed to generate CA: %v", err)
	}

	certPEM, keyPEM, err := generateSignedCertificate(testLocalName, []string{testLocalName}, caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	// Create a chain with cert + CA
	chainPEM := append(certPEM, caCertPEM...)

	if err := os.WriteFile(certFile, chainPEM, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	// Create reloader with 0 interval for testing
	reloader, err := newCertReloader(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate with full chain
	initialCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get initial certificate: %v", err)
	}

	initialChainLen := len(initialCert.Certificate)
	if initialChainLen < 2 {
		t.Fatalf("expected chain with at least 2 certificates, got %d", initialChainLen)
	}

	// Write shorter chain (just the cert, no CA)
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("failed to write shorter cert file: %v", err)
	}

	// Update mtime
	now := time.Now()
	os.Chtimes(certFile, now, now)
	os.Chtimes(keyFile, now, now)

	// Get certificate again - should still get the original (not the shorter chain)
	stillCert, err := reloader.GetCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get certificate: %v", err)
	}

	// Should still have the longer chain
	if len(stillCert.Certificate) != initialChainLen {
		t.Errorf("expected chain with %d certificates after guard, got %d", initialChainLen, len(stillCert.Certificate))
	}
}

// TestAllowedSANVerifierEmpty tests that empty allow-list accepts any cert.
func TestAllowedSANVerifierEmpty(t *testing.T) {
	verifier := allowedSANVerifier([]string{})

	certPEM, _, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err = verifier(cs)
	if err != nil {
		t.Errorf("expected no error for empty allow-list, got: %v", err)
	}
}

// TestAllowedSANVerifierAllows tests that verifier allows matching DNS names.
func TestAllowedSANVerifierAllows(t *testing.T) {
	allowed := []string{testLocalName}
	verifier := allowedSANVerifier(allowed)

	certPEM, _, err := generateTestCertificate(testLocalName, []string{testLocalName})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err = verifier(cs)
	if err != nil {
		t.Errorf("expected no error for matching DNS name, got: %v", err)
	}
}

// TestAllowedSANVerifierRejects tests that verifier rejects non-matching DNS names.
func TestAllowedSANVerifierRejects(t *testing.T) {
	allowed := []string{testLocalName}
	verifier := allowedSANVerifier(allowed)

	certPEM, _, err := generateTestCertificate("other.local", []string{"other.local"})
	if err != nil {
		t.Fatalf("failed to generate certificate: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	err = verifier(cs)
	if err == nil {
		t.Error("expected error for non-matching DNS name")
	}
}

// TestAllowedSANVerifierNoPeerCert tests that verifier rejects when no peer cert.
func TestAllowedSANVerifierNoPeerCert(t *testing.T) {
	allowed := []string{testLocalName}
	verifier := allowedSANVerifier(allowed)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}

	err := verifier(cs)
	if err == nil {
		t.Error("expected error when no peer certificate")
	}
}

// TestEndToEndWithAllowedSAN tests end-to-end mTLS with allowed SAN.
func TestEndToEndWithAllowedSAN(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate root CA
	caCertPEM, caKeyPEM, err := generateRootCA()
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}

	caCertFile := filepath.Join(tmpDir, "ca.pem")
	if err := os.WriteFile(caCertFile, caCertPEM, 0600); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	// Generate server certificate signed by CA
	serverCertPEM, serverKeyPEM, err := generateSignedCertificate("server.local", []string{"localhost"}, caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("failed to generate server certificate: %v", err)
	}

	serverCertFile := filepath.Join(tmpDir, "server.pem")
	serverKeyFile := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(serverCertFile, serverCertPEM, 0600); err != nil {
		t.Fatalf("failed to write server cert: %v", err)
	}
	if err := os.WriteFile(serverKeyFile, serverKeyPEM, 0600); err != nil {
		t.Fatalf("failed to write server key: %v", err)
	}

	// Generate client certificate with allowed SAN
	clientCertPEM, clientKeyPEM, err := generateSignedCertificate("client.local", []string{"client.local"}, caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("failed to generate client certificate: %v", err)
	}

	// Create TLS listener with reloader
	reloader, err := newCertReloader(serverCertFile, serverKeyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	tlsConfig := &tls.Config{
		GetCertificate:   reloader.GetCertificate,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        caPool,
		VerifyConnection: allowedSANVerifier([]string{"client.local"}),
	}

	listener, err := tls.Listen("tcp", "localhost:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	// Start simple HTTPS server
	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK")
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go server.Serve(listener) //nolint:errcheck

	// Create client with client cert
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("failed to load client certificate: %v", err)
	}

	clientTLSConfig := &tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: clientTLSConfig,
		},
	}

	// Make request - should succeed
	resp, err := client.Get(fmt.Sprintf("https://%s/test", listener.Addr()))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status OK, got: %v", resp.StatusCode)
	}
}
