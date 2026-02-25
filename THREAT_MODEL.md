# Threat Model — IoT Authentication Gateway

**Version:** 1.0
**Date:** 2025-01-01
**Scope:** Device authentication gateway, PKI, provisioning workflow, host OS

---

## 1. System Overview

The IoT Auth Gateway authenticates IoT devices using mutual TLS (mTLS) and
issues short-lived JWTs for subsequent API access. The system consists of:

| Component | Technology | Trust Level |
|---|---|---|
| Gateway server | Go, TLS 1.3 | Trusted |
| Provisioning service | Python | Trusted (offline / air-gapped preferred) |
| CA / PKI | OpenSSL / cryptography | High trust, air-gapped preferred |
| Device registry | SQLite | Trusted |
| Host OS | Linux (Debian/Ubuntu) | Hardened |
| IoT devices | Embedded Linux / RTOS | Untrusted until authenticated |
| Network | Internet / LAN | Untrusted |

### Data Flow

```
[IoT Device]
     |  (1) mTLS ClientHello — presents device cert signed by CA
     v
[Gateway :8443]
     |  (2) Verifies cert chain → CA, OU, revocation list
     |  (3) Issues signed JWT (ES256, 1-hour TTL)
     v
[Device holds JWT]
     |  (4) Bearer JWT on every /api/* request
     v
[Gateway validates JWT → proxies to Backend]
```

---

## 2. Assets

| Asset | Confidentiality | Integrity | Availability |
|---|---|---|---|
| CA private key | Critical | Critical | Medium |
| Device private keys | Critical | Critical | Medium |
| JWT signing key | Critical | Critical | High |
| Device registry (SQLite) | Medium | High | High |
| Audit logs | Low | High | High |
| Backend API data | High | High | High |
| Gateway binary | Low | High | High |

---

## 3. Threat Actors

| Actor | Capability | Motivation |
|---|---|---|
| Script kiddie | Low | Opportunistic credential theft |
| Insider / rogue device | Medium | Data exfiltration, lateral movement |
| Nation-state APT | High | Long-term espionage, supply chain |
| Disgruntled employee | Medium | Sabotage, credential leakage |

---

## 4. Threat Enumeration (STRIDE)

### 4.1 Credential Leakage

| ID | Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|---|
| CL-1 | CA private key exfiltration | Physical access to PKI host; malware | Medium | Critical | Air-gap CA host; HSM for CA key; strict file perms (0600) |
| CL-2 | Device private key stolen from device | Physical device theft; firmware dump | High | High | Per-device keys (blast radius = 1 device); revocation workflow |
| CL-3 | JWT signing key leak | Server compromise; env var in logs | Low | Critical | Key stored as file (0600); not in env; key rotation procedure |
| CL-4 | JWT interception | MitM on TLS connection | Very Low | High | TLS 1.3 only; HSTS; cert pinning on devices |
| CL-5 | Provisioning token interception | Insecure delivery channel | Medium | High | Out-of-band delivery; token is single-use; short TTL |

**Countermeasures in this codebase:**
- `auth/mtls.go`: TLS 1.3 minimum; `SessionTicketsDisabled`
- `auth/jwt.go`: ES256 (ECDSA P-256) — resists key brute-force
- `provisioning/provision.py`: `secrets.token_urlsafe(32)` provisioning token
- `harden_linux.sh`: `chmod 0600` on all key files; restricted log dir

---

### 4.2 Denial of Service (DoS)

| ID | Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|---|
| DOS-1 | TLS handshake flood | High-volume mTLS ClientHello | High | High | Rate limiter (per-IP); iptables connlimit; SYN cookies |
| DOS-2 | JWT validation flood | Forged / expired tokens at /api/* | Medium | Medium | In-process rate limiter; Fail2ban on auth failures |
| DOS-3 | Disk exhaustion via audit log | Log injection at high volume | Low | Medium | Log rotation (logrotate); disk quota on /var/log |
| DOS-4 | Connection pool exhaustion | Many slow TLS connections | Medium | High | ReadTimeout / WriteTimeout (30s); gateway process limits |
| DOS-5 | Host resource exhaustion | CPU/mem spike from crypto ops | Low | High | systemd resource limits; cgroup constraints |

**Countermeasures:**
- `gateway/server.go`: `ReadTimeout`, `WriteTimeout` on HTTP server
- `auth/middleware.go`: `RateLimiter` — per-IP failure window + ban
- `setup_iptables.sh`: SYN cookies; ICMP rate limit; port scan detection
- `configs/fail2ban/jail.local`: ban after 5 failures / 60s window
- `configs/systemd/iot-gateway.service`: `MemoryDenyWriteExecute`, resource controls

---

### 4.3 Certificate Compromise

| ID | Threat | Attack Vector | Likelihood | Impact | Mitigation |
|---|---|---|---|---|---|
| CC-1 | Rogue device using stolen cert | Physical device cloning | Low | High | Per-device certs; revocation endpoint + in-mem CRL |
| CC-2 | CA compromise → mass cert forgery | PKI host breach | Very Low | Critical | Air-gap CA; HSM; CA cert pinned in gateway config |
| CC-3 | Expired cert accepted | Clock skew on gateway | Low | Medium | TLS stack enforces expiry; Go `jwt.WithExpirationRequired()` |
| CC-4 | OU spoofing (cross-OU impersonation) | Cert with different OU | Low | High | `ValidatePeerCert` enforces OU = "IoT Devices" |
| CC-5 | Self-signed device cert bypassing CA | mTLS misconfiguration | Low | Critical | `tls.RequireAndVerifyClientCert`; CA pool explicitly set |
| CC-6 | Certificate serial collision | Weak serial RNG | Very Low | Low | `x509.random_serial_number()` uses CSPRNG |

**Countermeasures:**
- `auth/mtls.go`: `ClientAuth: tls.RequireAndVerifyClientCert`; CA pool pinned
- `auth/mtls.go`: `ValidatePeerCert` — OU check + in-memory revocation
- `gateway/handler.go`: `/admin/revoke` endpoint adds serial to runtime CRL
- `provisioning/ca_setup.py`: RSA-4096 CA key; `x509.random_serial_number()`

---

### 4.4 Spoofing & Tampering

| ID | Threat | Mitigation |
|---|---|---|
| SP-1 | JWT algorithm confusion (RS256 → HS256) | `auth/jwt.go` validates `alg` is ES256 before accepting |
| SP-2 | JWT `kid` header injection | No dynamic key lookup; single signing key |
| SP-3 | Audit log tampering | Log dir owned by `iot-gateway`; read-only for other users; integrity check via syslog forwarding |
| SP-4 | Replay of captured JWT | Short TTL (1h); `jti` (tokenID) can be added to deny list |
| SP-5 | HTTP header injection via X-Device-ID | Gateway overwrites header server-side; client cannot set it |

---

## 5. Residual Risks & Recommended Improvements

| Risk | Recommendation |
|---|---|
| In-memory revocation list is lost on restart | Persist CRL to disk or integrate OCSP; load on startup |
| Single JWT signing key (no rotation) | Implement key rotation with `kid` header and multi-key validation window |
| SQLite registry not replicated | Replace with a replicated store (Postgres, etcd) for HA deployments |
| No mutual auth on `/admin/revoke` | Protect with a separate admin mTLS client cert or network ACL |
| Provisioning token stored in plaintext in DB | Store only PBKDF2/Argon2 hash |
| No certificate transparency logging | Submit CA cert to CT logs for public auditability |

---

## 6. Security Testing Checklist

- [ ] Attempt connection without client certificate → expect 401
- [ ] Connect with cert from a different CA → expect TLS error
- [ ] Connect with revoked serial → expect 401
- [ ] Send >10 auth failures from one IP in 60s → expect ban (Fail2ban)
- [ ] Submit JWT with wrong algorithm (`alg: HS256`) → expect 401
- [ ] Submit expired JWT → expect 401 with `JWT_EXPIRED` audit event
- [ ] Flood `/auth/token` at 1000 req/s → expect rate limiting, no crash
- [ ] Port scan host → expect Fail2ban ban within 60s
- [ ] Attempt SSH password login → expect rejection
- [ ] Verify audit log entries for every auth event (success + failure)
