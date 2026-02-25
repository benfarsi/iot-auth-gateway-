package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/benfarsi/iot-auth-gateway/internal/logging"
)

// BearerMiddleware validates the Authorization: Bearer <jwt> header.
// It rejects requests whose JWT is missing, malformed, expired, or invalid.
func BearerMiddleware(tm *TokenManager, audit *logging.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			audit.JWT("", "", logging.EventJWTInvalid, false, "missing Bearer token")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		claims, err := tm.Validate(tokenStr)
		if err != nil {
			ev := logging.EventJWTInvalid
			if strings.Contains(err.Error(), "expired") {
				ev = logging.EventJWTExpired
			}
			audit.JWT("", "", ev, false, err.Error())
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		audit.JWT(claims.DeviceID, claims.ID, logging.EventJWTIssued, true, "token validated")
		// Propagate device identity via request header for downstream handlers.
		r.Header.Set("X-Device-ID", claims.DeviceID)
		r.Header.Set("X-Cert-Serial", claims.CertSerial)
		next.ServeHTTP(w, r)
	})
}

// failureEntry tracks recent auth failures for a single remote IP.
type failureEntry struct {
	count     int
	windowEnd time.Time
	bannedUntil time.Time
}

// RateLimiter tracks per-IP authentication failures and blocks repeat offenders.
// Failures are counted within a sliding 1-minute window; once the threshold is
// exceeded the IP is banned for the configured duration.
type RateLimiter struct {
	mu       sync.Mutex
	entries  map[string]*failureEntry
	maxFails int
	banDur   time.Duration
}

// NewRateLimiter constructs a limiter. maxFails is per 60-second window.
func NewRateLimiter(maxFails int, banDur time.Duration) *RateLimiter {
	return &RateLimiter{
		entries:  make(map[string]*failureEntry),
		maxFails: maxFails,
		banDur:   banDur,
	}
}

// RecordFailure registers a failed attempt from addr.
// Returns true if the IP is now banned.
func (rl *RateLimiter) RecordFailure(addr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	e, ok := rl.entries[addr]
	if !ok {
		e = &failureEntry{}
		rl.entries[addr] = e
	}

	// Reset window if expired.
	if now.After(e.windowEnd) {
		e.count = 0
		e.windowEnd = now.Add(60 * time.Second)
	}
	e.count++

	if e.count >= rl.maxFails {
		e.bannedUntil = now.Add(rl.banDur)
		return true
	}
	return false
}

// IsBanned reports whether addr is currently banned.
func (rl *RateLimiter) IsBanned(addr string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	e, ok := rl.entries[addr]
	if !ok {
		return false
	}
	return time.Now().Before(e.bannedUntil)
}
