#!/usr/bin/env bash
# setup_fail2ban.sh — Install and configure Fail2ban for the IoT gateway.
#
# Creates a custom filter that parses the gateway's structured JSON audit log
# and bans IPs that exceed the AUTH_FAILURE threshold.

set -euo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
fatal() { echo -e "${RED}[X]${NC} $*" >&2; exit 1; }

[[ $EUID -ne 0 ]] && fatal "Run as root."

command -v fail2ban-server &>/dev/null || {
    info "Installing fail2ban..."
    apt-get install -y fail2ban
}

FILTER_DIR=/etc/fail2ban/filter.d
JAIL_DIR=/etc/fail2ban/jail.d

info "Copying custom filter and jail config..."
cp configs/fail2ban/iot-gateway.conf  "$FILTER_DIR/iot-gateway.conf"
cp configs/fail2ban/jail.local        "$JAIL_DIR/iot-gateway.local"

info "Reloading Fail2ban..."
systemctl enable --now fail2ban
fail2ban-client reload

info "Fail2ban setup complete."
info "Monitor with: fail2ban-client status iot-gateway"
