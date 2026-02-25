package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/benfarsi/iot-auth-gateway/internal/auth"
	"github.com/benfarsi/iot-auth-gateway/internal/logging"
)

// tokenResponse is the JSON body returned by POST /auth/token.
type tokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	DeviceID  string    `json:"device_id"`
}

// handleToken authenticates the device via its mTLS client certificate and
// issues a short-lived JWT. This is the only endpoint that does NOT require
// a pre-existing Bearer token.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := remoteIP(r.RemoteAddr)

	// Rate-limit check before any expensive crypto work.
	if s.rateLimiter.IsBanned(ip) {
		s.audit.Log(logging.AuditRecord{
			Event:      logging.EventConnRejected,
			RemoteAddr: ip,
			Message:    "IP is currently banned",
			Success:    false,
		})
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// Extract the peer certificate verified by the TLS stack.
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		s.recordFailure(ip, "", "", "no client certificate presented")
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	cert := r.TLS.PeerCertificates[0]
	serial := auth.CertSerialHex(cert)

	// Additional application-layer cert validation (revocation, OU check).
	s.mu.RLock()
	revoked := s.revokedCerts
	s.mu.RUnlock()
	if err := auth.ValidatePeerCert(cert, revoked); err != nil {
		s.recordFailure(ip, "", serial, fmt.Sprintf("cert validation failed: %v", err))
		http.Error(w, "certificate rejected", http.StatusUnauthorized)
		return
	}

	deviceID, err := auth.DeviceIDFromCert(cert)
	if err != nil {
		s.recordFailure(ip, "", serial, "cannot extract device ID from cert CN")
		http.Error(w, "invalid certificate", http.StatusUnauthorized)
		return
	}

	signed, tokenID, err := s.tokenMgr.Issue(deviceID, serial)
	if err != nil {
		s.audit.JWT(deviceID, "", logging.EventJWTInvalid, false, "token signing failed: "+err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	s.audit.Auth(deviceID, ip, serial, true, "mTLS authentication successful")
	s.audit.JWT(deviceID, tokenID, logging.EventJWTIssued, true, "JWT issued")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		Token:     signed,
		ExpiresAt: time.Now().Add(s.cfg.JWT.TokenTTL),
		DeviceID:  deviceID,
	})
}

// handleProxy reverse-proxies authenticated requests to the backend service.
// The BearerMiddleware must wrap this handler to ensure JWT validation.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Gateway.BackendAddr == "" {
		http.Error(w, "no backend configured", http.StatusServiceUnavailable)
		return
	}
	target, err := url.Parse(s.cfg.Gateway.BackendAddr)
	if err != nil {
		http.Error(w, "invalid backend URL", http.StatusInternalServerError)
		return
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ServeHTTP(w, r)
}

// handleHealth returns a simple liveness response (no auth required).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

// handleRevoke adds a certificate serial to the revocation list.
// In production this endpoint should be protected by an admin mTLS cert or network ACL.
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Serial == "" {
		http.Error(w, "serial required", http.StatusBadRequest)
		return
	}
	s.RevokeSerial(body.Serial)
	w.WriteHeader(http.StatusNoContent)
}

// recordFailure registers a failed auth attempt, triggers rate-limiting, and
// writes an audit record. The structured log line is also parseable by Fail2ban.
func (s *Server) recordFailure(ip, deviceID, serial, reason string) {
	s.audit.Auth(deviceID, ip, serial, false, reason)
	if s.rateLimiter.RecordFailure(ip) {
		s.audit.RateLimit(ip, 0)
	}
}
