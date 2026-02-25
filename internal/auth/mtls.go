// Package auth provides mTLS verification and JWT issuance/validation.
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// LoadCA reads the PEM-encoded CA certificate used to verify device certs.
func LoadCA(caCertPath string) (*x509.CertPool, error) {
	pemData, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, errors.New("no valid PEM certificates found in CA file")
	}
	return pool, nil
}

// ServerTLSConfig builds a *tls.Config that:
//   - presents the gateway's server certificate
//   - requires and verifies client certificates (mTLS)
//   - restricts to TLS 1.3 only
func ServerTLSConfig(caCertPath, serverCertPath, serverKeyPath string) (*tls.Config, error) {
	caPool, err := LoadCA(caCertPath)
	if err != nil {
		return nil, err
	}

	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		// Disable session tickets to prevent ticket-based resumption attacks.
		SessionTicketsDisabled: true,
		// CipherSuites left nil — Go 1.17+ selects secure defaults for TLS 1.3.
	}
	return cfg, nil
}

// DeviceIDFromCert extracts the device identifier from the certificate's
// Common Name. Callers should use this after mTLS verification succeeds.
func DeviceIDFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", errors.New("nil certificate")
	}
	if cert.Subject.CommonName == "" {
		return "", errors.New("certificate has empty Common Name")
	}
	return cert.Subject.CommonName, nil
}

// CertSerialHex returns the certificate serial number as a hex string,
// suitable for audit log records.
func CertSerialHex(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return fmt.Sprintf("%X", cert.SerialNumber)
}

// ValidatePeerCert performs additional checks beyond what Go's TLS stack
// verifies automatically (expiry, chain). It enforces:
//   - The cert was issued by the expected OU "IoT Devices"
//   - The cert is not on the (in-memory) revocation list
func ValidatePeerCert(cert *x509.Certificate, revoked map[string]bool) error {
	serial := CertSerialHex(cert)
	if revoked[serial] {
		return fmt.Errorf("certificate serial %s has been revoked", serial)
	}
	// Enforce organisational unit to prevent cross-OU impersonation.
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == "IoT Devices" {
			return nil
		}
	}
	return errors.New("certificate OU does not include 'IoT Devices'")
}
