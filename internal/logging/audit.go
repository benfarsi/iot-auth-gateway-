// Package logging provides structured audit logging for all authentication events.
// Every entry is written as a single JSON line to enable downstream SIEM ingestion.
package logging

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// EventType classifies the audit record.
type EventType string

const (
	EventAuthSuccess    EventType = "AUTH_SUCCESS"
	EventAuthFailure    EventType = "AUTH_FAILURE"
	EventCertInvalid    EventType = "CERT_INVALID"
	EventCertExpired    EventType = "CERT_EXPIRED"
	EventJWTIssued      EventType = "JWT_ISSUED"
	EventJWTInvalid     EventType = "JWT_INVALID"
	EventJWTExpired     EventType = "JWT_EXPIRED"
	EventProvision      EventType = "DEVICE_PROVISIONED"
	EventRevoke         EventType = "DEVICE_REVOKED"
	EventRateLimit      EventType = "RATE_LIMIT_TRIGGERED"
	EventConnAccepted   EventType = "CONN_ACCEPTED"
	EventConnRejected   EventType = "CONN_REJECTED"
	EventServerStart    EventType = "SERVER_START"
	EventServerStop     EventType = "SERVER_STOP"
)

// AuditRecord is the canonical log entry. All fields are exported for JSON serialisation.
type AuditRecord struct {
	Timestamp  time.Time         `json:"timestamp"`
	Event      EventType         `json:"event"`
	DeviceID   string            `json:"device_id,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	CertSerial string            `json:"cert_serial,omitempty"`
	TokenID    string            `json:"token_id,omitempty"`
	Message    string            `json:"message,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Success    bool              `json:"success"`
}

// Logger writes newline-delimited JSON audit records.
type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

// New creates a Logger. Pass os.Stdout or an *os.File.
func New(out io.Writer) *Logger {
	if out == nil {
		out = os.Stdout
	}
	return &Logger{out: out}
}

// NewFile opens (or creates) a file for append-only audit writing.
func NewFile(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return New(f), nil
}

// Log writes a single audit record. It is safe for concurrent use.
func (l *Logger) Log(r AuditRecord) {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(r)
	if err != nil {
		// Fallback: write a minimal record indicating the marshalling failure.
		data = []byte(`{"event":"MARSHAL_ERROR","success":false}`)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.out.Write(append(data, '\n'))
}

// Auth logs an authentication event (success or failure).
func (l *Logger) Auth(deviceID, remoteAddr, certSerial string, success bool, msg string) {
	ev := EventAuthFailure
	if success {
		ev = EventAuthSuccess
	}
	l.Log(AuditRecord{
		Event:      ev,
		DeviceID:   deviceID,
		RemoteAddr: remoteAddr,
		CertSerial: certSerial,
		Message:    msg,
		Success:    success,
	})
}

// JWT logs a token issuance or validation event.
func (l *Logger) JWT(deviceID, tokenID string, ev EventType, success bool, msg string) {
	l.Log(AuditRecord{
		Event:    ev,
		DeviceID: deviceID,
		TokenID:  tokenID,
		Message:  msg,
		Success:  success,
	})
}

// RateLimit logs a rate-limit or ban trigger.
func (l *Logger) RateLimit(remoteAddr string, failures int) {
	l.Log(AuditRecord{
		Event:      EventRateLimit,
		RemoteAddr: remoteAddr,
		Message:    "connection rate limit exceeded",
		Success:    false,
		Details:    map[string]string{"failures": string(rune('0' + failures%10))},
	})
}
