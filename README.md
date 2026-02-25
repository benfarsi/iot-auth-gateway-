# IoT Authentication & Gateway Service

A production-grade IoT device authentication gateway using mutual TLS, signed provisioning, and short-lived JWTs. Built in Go + Python, hardened for Linux deployment.

## Architecture

```
IoT Device  ──mTLS──►  Gateway (:8443)  ──JWT proxy──►  Backend API
                           │
                     Audit Logger (JSON)
                           │
                       Fail2ban  ──ban──►  iptables DROP
```

## Components

| Path | Language | Purpose |
|---|---|---|
| `cmd/gateway/` | Go | Main gateway binary |
| `internal/auth/` | Go | mTLS verification, JWT issue/validate, rate limiter |
| `internal/gateway/` | Go | HTTP server, handlers, reverse proxy |
| `internal/logging/` | Go | Structured JSON audit logger |
| `provisioning/ca_setup.py` | Python | Bootstrap CA + server certificates |
| `provisioning/provision.py` | Python | Issue signed device certificates |
| `provisioning/device_registry.py` | Python | SQLite device registry |
| `scripts/harden_linux.sh` | Bash | SSH hardening, sysctl, service disabling |
| `scripts/setup_iptables.sh` | Bash | Firewall rules (INPUT DROP default) |
| `scripts/setup_fail2ban.sh` | Bash | Install Fail2ban with custom gateway filter |
| `configs/` | YAML/INI | Gateway, Fail2ban, systemd configs |
| `THREAT_MODEL.md` | Markdown | STRIDE threat model |

## Quick Start

### 1. Bootstrap PKI

```bash
pip install cryptography
python3 provisioning/ca_setup.py --pki-dir pki/ca --san-ip 0.0.0.0
```

### 2. Generate JWT Signing Key

```bash
go run ./cmd/gateway -gen-key -key-out pki/jwt-signing.key
```

### 3. Provision a Device

```bash
python3 provisioning/provision.py --device-id sensor-001
# delivers: pki/devices/sensor-001.crt + sensor-001.key
```

### 4. Build and Run Gateway

```bash
go mod download
go build -o bin/gateway ./cmd/gateway
./bin/gateway -config configs/gateway.yaml
```

### 5. Device Authentication Flow

```bash
# Step 1: Exchange cert for JWT
curl -s --cert pki/devices/sensor-001.crt \
        --key  pki/devices/sensor-001.key \
        --cacert pki/ca/ca.crt \
        -X POST https://localhost:8443/auth/token

# Step 2: Use JWT for API calls
TOKEN="<jwt from step 1>"
curl -s --cacert pki/ca/ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://localhost:8443/api/data
```

## Server Hardening (Production)

```bash
sudo bash scripts/harden_linux.sh       # SSH, sysctl, perms
sudo bash scripts/setup_iptables.sh     # Firewall
sudo bash scripts/setup_fail2ban.sh     # Intrusion blocking
sudo cp configs/systemd/iot-gateway.service /etc/systemd/system/
sudo systemctl enable --now iot-gateway
```

## Security Properties

- **TLS 1.3 only** — no downgrade path
- **mTLS required** — every device must present a CA-signed cert
- **OU enforcement** — only certs with `OU=IoT Devices` accepted
- **In-memory CRL** — revoked serials rejected immediately without restart
- **ES256 JWTs** — ECDSA P-256; `alg` validated before key lookup
- **Per-IP rate limiting** — ban after configurable failure threshold
- **Fail2ban integration** — iptables ban from JSON audit log
- **systemd sandboxing** — `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`
- **Structured audit log** — every auth event (success + failure) is JSON-logged

## Threat Model

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full STRIDE analysis covering credential leakage, denial-of-service, and certificate compromise attack surfaces.
