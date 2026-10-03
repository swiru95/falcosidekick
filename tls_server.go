// SPDX-License-Identifier: MIT OR Apache-2.0

package main

import (
	"crypto/tls"
	"fmt"
)

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
