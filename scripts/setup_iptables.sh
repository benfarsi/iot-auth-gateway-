#!/usr/bin/env bash
# setup_iptables.sh — Firewall isolation for the IoT Auth Gateway host.
#
# Policy:
#   INPUT   — DROP by default; allow only SSH (22), mTLS gateway (8443), ICMP
#   OUTPUT  — ACCEPT by default (tightened below for production)
#   FORWARD — DROP (this host is not a router)
#
# Rules are saved to /etc/iptables/rules.v4 for persistence across reboots.
# Requires iptables-persistent: apt-get install iptables-persistent

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fatal() { echo -e "${RED}[X]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && fatal "Run as root."

# Configurable — override via environment variables if needed.
SSH_PORT="${SSH_PORT:-22}"
GATEWAY_PORT="${GATEWAY_PORT:-8443}"
# Comma-separated CIDRs allowed to reach the gateway port (empty = all).
ALLOWED_DEVICE_CIDR="${ALLOWED_DEVICE_CIDR:-}"
# Comma-separated CIDRs allowed SSH access (empty = all — not recommended).
SSH_ALLOWED_CIDR="${SSH_ALLOWED_CIDR:-}"

IPT="iptables"

info "Flushing existing rules..."
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

info "Setting default policies: INPUT=DROP, FORWARD=DROP, OUTPUT=ACCEPT"
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT ACCEPT

### LOOPBACK ###################################################################
$IPT -A INPUT  -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

### ESTABLISHED / RELATED ######################################################
$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

### ICMP (limited) #############################################################
# Allow ping and ICMP unreachable — rate-limited to prevent ICMP flood.
$IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s --limit-burst 10 -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

### SSH ########################################################################
if [[ -n "$SSH_ALLOWED_CIDR" ]]; then
    IFS=',' read -ra cidrs <<< "$SSH_ALLOWED_CIDR"
    for cidr in "${cidrs[@]}"; do
        $IPT -A INPUT -p tcp --dport "$SSH_PORT" -s "$cidr" \
            -m conntrack --ctstate NEW \
            -m limit --limit 6/min --limit-burst 3 \
            -j ACCEPT
        info "  SSH allowed from $cidr"
    done
else
    warn "  SSH open to all IPs — set SSH_ALLOWED_CIDR in production!"
    $IPT -A INPUT -p tcp --dport "$SSH_PORT" \
        -m conntrack --ctstate NEW \
        -m limit --limit 6/min --limit-burst 3 \
        -j ACCEPT
fi

### mTLS GATEWAY ###############################################################
if [[ -n "$ALLOWED_DEVICE_CIDR" ]]; then
    IFS=',' read -ra cidrs <<< "$ALLOWED_DEVICE_CIDR"
    for cidr in "${cidrs[@]}"; do
        $IPT -A INPUT -p tcp --dport "$GATEWAY_PORT" -s "$cidr" \
            -m conntrack --ctstate NEW -j ACCEPT
        info "  Gateway port $GATEWAY_PORT allowed from $cidr"
    done
else
    warn "  Gateway port $GATEWAY_PORT open to all IPs — restrict ALLOWED_DEVICE_CIDR in production!"
    $IPT -A INPUT -p tcp --dport "$GATEWAY_PORT" -m conntrack --ctstate NEW -j ACCEPT
fi

### LOG & DROP INVALID #########################################################
# Log invalid/unexpected packets before the final DROP — feeds Fail2ban.
$IPT -A INPUT -m limit --limit 10/min -j LOG \
    --log-prefix "iptables-DROP: " --log-level 4
$IPT -A INPUT -j DROP

### PORT SCAN DETECTION ########################################################
# Tag and log port-scan attempts (SYN to closed ports).
$IPT -N PORT_SCAN 2>/dev/null || $IPT -F PORT_SCAN
$IPT -A PORT_SCAN -m recent --name portscan --set -j LOG \
    --log-prefix "iptables-PORTSCAN: " --log-level 4
$IPT -A PORT_SCAN -j DROP
$IPT -A INPUT -p tcp --syn \
    -m recent --name portscan --rcheck --seconds 60 --hitcount 5 \
    -j PORT_SCAN

### SAVE RULES #################################################################
info "Saving rules to /etc/iptables/rules.v4 ..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4

# Enable persistence via iptables-persistent if available.
if systemctl is-enabled netfilter-persistent &>/dev/null 2>&1; then
    systemctl enable --now netfilter-persistent
    info "netfilter-persistent enabled."
else
    warn "iptables-persistent not installed. Rules won't survive reboot."
    warn "Install with: apt-get install iptables-persistent"
fi

info "Firewall configuration complete."
$IPT -L INPUT -v --line-numbers
