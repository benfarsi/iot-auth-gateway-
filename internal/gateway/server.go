// Package gateway wires together the mTLS listener, authentication handlers,
// rate limiter, and audit logger into the runnable gateway server.
package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/benfarsi/iot-auth-gateway/internal/auth"
	"github.com/benfarsi/iot-auth-gateway/internal/config"
	"github.com/benfarsi/iot-auth-gateway/internal/logging"
)

// Server is the IoT authentication gateway.
type Server struct {
	cfg         *config.Config
	tlsCfg      *tls.Config
	tokenMgr    *auth.TokenManager
	rateLimiter *auth.RateLimiter
	audit       *logging.Logger
	httpSrv     *http.Server
	// revokedCerts holds certificate serial numbers that must be rejected.
	// In production this would be loaded from a CRL or OCSP source.
	revokedCerts map[string]bool
	mu           sync.RWMutex
}

// New constructs a Server from the supplied configuration.
func New(cfg *config.Config, audit *logging.Logger) (*Server, error) {
	tlsCfg, err := auth.ServerTLSConfig(
		cfg.TLS.CACertFile,
		cfg.TLS.ServerCertFile,
		cfg.TLS.ServerKeyFile,
	)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}

	tokenMgr, err := auth.NewTokenManagerFromFile(
		cfg.JWT.SigningKeyFile,
		cfg.JWT.Issuer,
		cfg.JWT.TokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("JWT manager: %w", err)
	}

	rl := auth.NewRateLimiter(cfg.RateLimit.MaxFailuresPerMin, cfg.RateLimit.BanDuration)

	s := &Server{
		cfg:          cfg,
		tlsCfg:       tlsCfg,
		tokenMgr:     tokenMgr,
		rateLimiter:  rl,
		audit:        audit,
		revokedCerts: make(map[string]bool),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/token", s.handleToken)
	mux.Handle("/api/", auth.BearerMiddleware(tokenMgr, audit, http.HandlerFunc(s.handleProxy)))
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/admin/revoke", s.handleRevoke)

	s.httpSrv = &http.Server{
		Addr:         cfg.Gateway.ListenAddr,
		Handler:      mux,
		TLSConfig:    tlsCfg,
		ReadTimeout:  cfg.Gateway.ReadTimeout,
		WriteTimeout: cfg.Gateway.WriteTimeout,
	}
	return s, nil
}

// Run starts the mTLS HTTPS server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := tls.Listen("tcp", s.cfg.Gateway.ListenAddr, s.tlsCfg)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	s.audit.Log(logging.AuditRecord{
		Event:   logging.EventServerStart,
		Message: fmt.Sprintf("gateway listening on %s", s.cfg.Gateway.ListenAddr),
		Success: true,
	})

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.httpSrv.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutCtx); err != nil {
			log.Printf("graceful shutdown error: %v", err)
		}
		s.audit.Log(logging.AuditRecord{
			Event:   logging.EventServerStop,
			Message: "gateway shut down gracefully",
			Success: true,
		})
		return nil
	case err := <-errCh:
		return err
	}
}

// RevokeSerial adds a certificate serial to the in-memory revocation list.
func (s *Server) RevokeSerial(serial string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokedCerts[serial] = true
	s.audit.Log(logging.AuditRecord{
		Event:      logging.EventRevoke,
		CertSerial: serial,
		Message:    "certificate added to revocation list",
		Success:    true,
	})
}

// remoteIP strips the port from a RemoteAddr string.
func remoteIP(addr string) string {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return ip
}
