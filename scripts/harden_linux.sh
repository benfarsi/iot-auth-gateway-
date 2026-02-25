#!/usr/bin/env bash
# harden_linux.sh — Baseline Linux hardening for the IoT gateway host.
#
# Applies:
#   1. SSH key-only authentication (disables password + root login)
#   2. Kernel sysctl hardening (network stack, core dumps)
#   3. File permission hardening on sensitive paths
#   4. Login banner for legal/forensic notice
#   5. Disable unused services (cups, avahi, bluetooth)
#
# Run as root on a fresh Debian/Ubuntu system BEFORE opening the gateway port.
# Safe to re-run (idempotent).

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fatal() { echo -e "${RED}[X]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && fatal "Run as root."

### 1. SSH HARDENING ###########################################################
info "Hardening SSH configuration..."
SSHD=/etc/ssh/sshd_config

# Back up original only once.
[[ ! -f "${SSHD}.orig" ]] && cp "$SSHD" "${SSHD}.orig"

apply_sshd() {
    local key="$1" val="$2"
    if grep -qE "^\s*#?\s*${key}" "$SSHD"; then
        sed -i "s|^\s*#\?\s*${key}.*|${key} ${val}|" "$SSHD"
    else
        echo "${key} ${val}" >> "$SSHD"
    fi
}

apply_sshd PermitRootLogin            no
apply_sshd PasswordAuthentication     no
apply_sshd ChallengeResponseAuthentication no
apply_sshd UsePAM                     yes
apply_sshd PubkeyAuthentication       yes
apply_sshd AuthorizedKeysFile         ".ssh/authorized_keys"
apply_sshd PermitEmptyPasswords       no
apply_sshd X11Forwarding              no
apply_sshd AllowTcpForwarding         no
apply_sshd MaxAuthTries               3
apply_sshd LoginGraceTime             20
apply_sshd ClientAliveInterval        300
apply_sshd ClientAliveCountMax        2
apply_sshd Protocol                   2
apply_sshd LogLevel                   VERBOSE

# Restrict to modern ciphers / MACs.
apply_sshd Ciphers         "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
apply_sshd MACs            "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
apply_sshd KexAlgorithms   "curve25519-sha256,diffie-hellman-group16-sha512"

systemctl reload sshd
info "SSH hardened. Password auth disabled. Root login disabled."

### 2. SYSCTL NETWORK HARDENING ###############################################
info "Applying sysctl hardening..."
cat > /etc/sysctl.d/99-iot-gateway.conf << 'EOF'
# Disable IP source routing and redirects.
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Enable SYN cookies to resist SYN flood DoS.
net.ipv4.tcp_syncookies = 1

# Ignore ICMP broadcasts.
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Log martian (spoofed) packets.
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Reverse path filtering.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable IPv6 if not used.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Disable core dumps for setuid binaries.
fs.suid_dumpable = 0

# Restrict /proc/PID visibility.
kernel.yama.ptrace_scope = 1

# Randomise virtual address space (ASLR).
kernel.randomize_va_space = 2
EOF

sysctl --system -q
info "Sysctl hardening applied."

### 3. FILE PERMISSION HARDENING ###############################################
info "Tightening file permissions..."
chmod 700 /root
chmod 600 /etc/shadow 2>/dev/null || true
chmod 644 /etc/passwd
chmod 600 /etc/gshadow 2>/dev/null || true

# Restrict cron to root only.
touch /etc/cron.allow
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow

# Ensure no world-writable directories in PATH.
for dir in /usr/local/sbin /usr/local/bin /usr/sbin /usr/bin /sbin /bin; do
    chmod o-w "$dir" 2>/dev/null || true
done

### 4. LOGIN BANNER ############################################################
info "Installing legal login banner..."
cat > /etc/issue.net << 'EOF'
******************************************************************************
  AUTHORISED ACCESS ONLY — IoT Authentication Gateway Host
  Unauthorised access or use is strictly prohibited and may be subject to
  civil and criminal prosecution. All sessions are monitored and logged.
******************************************************************************
EOF
apply_sshd Banner /etc/issue.net

### 5. DISABLE UNUSED SERVICES ################################################
info "Disabling unused services..."
for svc in cups avahi-daemon bluetooth ModemManager; do
    if systemctl is-enabled "$svc" &>/dev/null; then
        systemctl disable --now "$svc"
        info "  Disabled: $svc"
    fi
done

### 6. CREATE GATEWAY USER ####################################################
info "Creating unprivileged 'iot-gateway' service user..."
if ! id iot-gateway &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin iot-gateway
    info "  User 'iot-gateway' created."
else
    warn "  User 'iot-gateway' already exists."
fi

### 7. LOG DIRECTORIES #########################################################
info "Creating audit log directory..."
mkdir -p /var/log/iot-gateway
chown iot-gateway:iot-gateway /var/log/iot-gateway
chmod 750 /var/log/iot-gateway

info "Linux hardening complete."
echo ""
warn "NEXT STEPS:"
echo "  1. Run scripts/setup_iptables.sh to configure the firewall."
echo "  2. Run scripts/setup_fail2ban.sh to enable intrusion blocking."
echo "  3. Run python3 provisioning/ca_setup.py to bootstrap the PKI."
echo "  4. Deploy the gateway binary and enable iot-gateway.service."
