// SPDX-License-Identifier: MIT OR Apache-2.0

package certreload

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
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

// TestReloaderReloadsOnChange tests that the reloader detects and loads new certificates.
func TestReloaderReloadsOnChange(t *testing.T) {
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
	reloader, err := New(certFile, keyFile, 0)
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

// TestReloaderKeepsPreviousOnError tests that reloader keeps serving old cert on errors.
func TestReloaderKeepsPreviousOnError(t *testing.T) {
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
	reloader, err := New(certFile, keyFile, 0)
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

// TestClientCertReloaderReloadsOnChange tests that client cert reloader detects and loads new certificates.
func TestClientCertReloaderReloadsOnChange(t *testing.T) {
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
	reloader, err := New(certFile, keyFile, 0)
	if err != nil {
		t.Fatalf("failed to create reloader: %v", err)
	}

	// Get initial certificate
	initialCert, err := reloader.GetClientCertificate(nil)
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
	newCert, err := reloader.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("failed to get new certificate: %v", err)
	}

	// Verify certificates are different
	if initialCert == newCert {
		t.Error("expected different certificate after reload")
	}
}

// TestReloaderChainShrinkGuard tests that shorter certificate chains are not swapped in.
func TestReloaderChainShrinkGuard(t *testing.T) {
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
	reloader, err := New(certFile, keyFile, 0)
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
