// SPDX-License-Identifier: MIT OR Apache-2.0

package outputs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/falcosidekick/internal/pkg/certreload"
	"github.com/falcosecurity/falcosidekick/types"
)

const (
	certBlockType       = "CERTIFICATE"
	privateKeyBlockType = "PRIVATE KEY"
)

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

// generateServerCertificate generates a server certificate with IP SANs.
func generateServerCertificate(caCertPEM, caKeyPEM []byte) (certPEM, keyPEM []byte, err error) {
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
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// TestClientMTLSReload verifies that client certificates are hot-reloaded during requests.
// It sets up:
// 1. A TLS server that requires and verifies client certificates
// 2. Records the serial number of the client certificate presented
// 3. Creates an Output Client with mutual TLS
// 4. Makes an initial POST request
// 5. Replaces the client certificate files with a new one
// 6. Makes a second POST request on a fresh connection
// 7. Verifies the server saw a different certificate serial
func TestClientMTLSReload(t *testing.T) {
	// Use a test hook to disable the reload interval check
	// This allows us to test certificate reloads without sleeping 30 seconds
	zeroInterval := time.Duration(0)
	oldTestInterval := certreload.TestInterval
	certreload.TestInterval = &zeroInterval
	t.Cleanup(func() {
		certreload.TestInterval = oldTestInterval
	})

	// Create temporary directory for certificates
	tmpDir := t.TempDir()

	// Certificate file paths for client
	clientCertFile := filepath.Join(tmpDir, "client.crt")
	clientKeyFile := filepath.Join(tmpDir, "client.key")
	caCertFile := filepath.Join(tmpDir, "ca.crt")

	// Generate CA certificate
	caCertPEM, caKeyPEM, err := generateRootCA()
	require.NoError(t, err)

	err = os.WriteFile(caCertFile, caCertPEM, 0600)
	require.NoError(t, err)

	// Generate server certificate (signed by CA)
	// Note: will generate the certificate with IPs in the SANs
	serverCertPEM, serverKeyPEM, err := generateServerCertificate(caCertPEM, caKeyPEM)
	require.NoError(t, err)

	// Generate initial client certificate (signed by CA)
	clientCertPEM1, clientKeyPEM1, err := generateSignedCertificate(
		"client1", []string{}, caCertPEM, caKeyPEM)
	require.NoError(t, err)

	// Write initial client certificate
	err = os.WriteFile(clientCertFile, clientCertPEM1, 0600)
	require.NoError(t, err)
	err = os.WriteFile(clientKeyFile, clientKeyPEM1, 0600)
	require.NoError(t, err)

	// Parse CA cert for server TLS config
	caCertBlock, _ := pem.Decode(caCertPEM)
	_, err = x509.ParseCertificate(caCertBlock.Bytes)
	require.NoError(t, err)

	// Create server TLS config
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	// Track presented client certificate serials
	var presentedSerials []*big.Int
	var serialLock sync.Mutex

	// Create TLS server that records client cert serials
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			clientCert := r.TLS.PeerCertificates[0]
			serialLock.Lock()
			presentedSerials = append(presentedSerials, clientCert.SerialNumber)
			serialLock.Unlock()
		}
		// Force connection closure to ensure new TLS handshake on next request
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Handler:           handler,
		TLSConfig:         serverTLSConf,
		ReadHeaderTimeout: time.Second,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	tlsListener := tls.NewListener(listener, serverTLSConf)
	defer tlsListener.Close()

	serverURL := fmt.Sprintf("https://%s", tlsListener.Addr().String())

	// Start server in background
	go func() {
		server.Serve(tlsListener)
	}()
	defer server.Close()

	// Create output client with mutual TLS
	config := &types.Configuration{}
	config.MutualTLSClient.CertFile = clientCertFile
	config.MutualTLSClient.KeyFile = clientKeyFile
	config.MutualTLSClient.CaCertFile = caCertFile

	initClientArgs := &types.InitClientArgs{
		Config:    config,
		Stats:     &types.Statistics{},
		PromStats: &types.PromStatistics{},
	}

	nc, err := NewClient("test", serverURL, types.CommonConfig{MutualTLS: true, CheckCert: true}, *initClientArgs)
	require.Nil(t, err)
	require.NotEmpty(t, nc)

	// Make first POST request
	err = nc.Post("")
	require.NoError(t, err)

	// Extract the first certificate's serial
	require.Len(t, presentedSerials, 1)
	firstSerial := presentedSerials[0]

	// Generate a second client certificate with a different serial
	clientCertPEM2, clientKeyPEM2, err := generateSignedCertificate(
		"client2", []string{}, caCertPEM, caKeyPEM)
	require.NoError(t, err)

	// Wait a bit to ensure different timestamp
	time.Sleep(10 * time.Millisecond)

	// Rewrite the client certificate files
	err = os.WriteFile(clientCertFile, clientCertPEM2, 0600)
	require.NoError(t, err)
	err = os.WriteFile(clientKeyFile, clientKeyPEM2, 0600)
	require.NoError(t, err)

	// Make second POST request with the same client
	// The server sends "Connection: close" header, forcing a new TLS handshake
	err = nc.Post("")
	require.NoError(t, err)

	// Verify we received requests with different certificates
	require.Len(t, presentedSerials, 2)
	secondSerial := presentedSerials[1]

	// Verify the serials are different
	require.NotEqual(t, firstSerial.String(), secondSerial.String(),
		"Expected different certificate serials: first=%s, second=%s",
		firstSerial.String(), secondSerial.String())
}
