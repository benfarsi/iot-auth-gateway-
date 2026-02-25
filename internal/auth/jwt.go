package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// DeviceClaims are the JWT payload fields issued to authenticated IoT devices.
type DeviceClaims struct {
	DeviceID string `json:"device_id"`
	CertSerial string `json:"cert_serial"`
	jwt.RegisteredClaims
}

// TokenManager signs and validates device JWTs using ECDSA P-256.
type TokenManager struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
	ttl        time.Duration
}

// NewTokenManagerFromFile loads an ECDSA private key from a PEM file.
// The public key is derived automatically.
func NewTokenManagerFromFile(keyPath, issuer string, ttl time.Duration) (*TokenManager, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read JWT signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in JWT signing key file")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	return &TokenManager{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
		issuer:     issuer,
		ttl:        ttl,
	}, nil
}

// GenerateKeyFile creates a new P-256 ECDSA key and writes it as PEM.
// Use this during initial server setup, not in production hot paths.
func GenerateKeyFile(path string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// Issue creates a signed JWT for the given device.
func (tm *TokenManager) Issue(deviceID, certSerial string) (string, string, error) {
	tokenID := uuid.New().String()
	now := time.Now().UTC()
	claims := DeviceClaims{
		DeviceID:   deviceID,
		CertSerial: certSerial,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID,
			Issuer:    tm.issuer,
			Subject:   deviceID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.ttl)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(tm.privateKey)
	if err != nil {
		return "", "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, tokenID, nil
}

// Validate parses and verifies a JWT string. Returns the claims on success.
func (tm *TokenManager) Validate(tokenStr string) (*DeviceClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &DeviceClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return tm.publicKey, nil
	}, jwt.WithIssuer(tm.issuer), jwt.WithExpirationRequired())

	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*DeviceClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}
	return claims, nil
}
