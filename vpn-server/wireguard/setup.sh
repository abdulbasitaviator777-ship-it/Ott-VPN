#!/bin/bash
# OTT VPN — Full gateway setup script
# Run as root on a fresh Ubuntu 22.04 LTS server in India
#
# This script:
#   1. Installs WireGuard, Unbound, UFW, iptables
#   2. Generates server keys and config
#   3. Configures firewall
#   4. Installs and starts the peer manager
#   5. Configures Unbound DNS resolver
#   6. Enables IP forwarding and kill switch

set -euo pipefail

CITY="${CITY:-Mumbai}"
REGION="${REGION:-Maharashtra}"
ENDPOINT_HOST="${ENDPOINT_HOST:-$(curl -s https://api.ipify.org)}"
LISTEN_PORT="${LISTEN_PORT:-51820}"

echo "=== OTT VPN Gateway Setup ==="
echo "Location: $CITY, $REGION"
echo "Endpoint: $ENDPOINT_HOST:$LISTEN_PORT"

# --- 1. Install packages ---
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard unbound ufw iptables iproute2 python3 python3-pip dnsutils curl > /dev/null

# --- 2. Generate WireGuard server config ---
python3 /opt/ottvpn/vpn-server/wireguard/generate_server_config.py \
    --country IN \
    --city "$CITY" \
    --region "$REGION" \
    --port "$LISTEN_PORT" \
    --endpoint-hostname "$ENDPOINT_HOST" \
    --install-peer-manager

# --- 3. Firewall ---
bash /opt/ottvpn/vpn-server/firewall/rules.sh

# --- 4. DNS (Unbound) ---
cp /opt/ottvpn/vpn-server/dns/unbound.conf /etc/unbound/unbound.conf.d/ottvpn.conf
systemctl restart unbound

# --- 5. Start WireGuard ---
wg-quick up wg0

# --- 6. Install peer manager systemd service ---
cat > /etc/systemd/system/ottvpn-peer-manager.service << 'SVC'
[Unit]
Description=OTT VPN Peer Manager
After=wg-quick@wg0.service

[Service]
Type=simple
User=ottvpn
Environment=WG_INTERFACE=wg0
Environment=WG_TUNNEL_NET_V4=10.66.0.0/24
Environment=WG_TUNNEL_NET_V6=fd86::/64
ExecStart=/usr/bin/python3 /opt/ottvpn-peer-manager/peer_manager.py --port 9123
Restart=on-failure

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload
systemctl enable --now ottvpn-peer-manager

# --- 7. Health check timer ---
cat > /etc/systemd/system/ottvpn-health.service << 'HSVC'
[Unit]
Description=OTT VPN Health Check
After=wg-quick@wg0.service

[Service]
Type=oneshot
User=ottvpn
ExecStart=/usr/bin/python3 /opt/ottvpn/vpn-server/monitoring/health_check.py
HSVC

cat > /etc/systemd/system/ottvpn-health.timer << 'HTMR'
[Unit]
Description=Run OTT VPN health check every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
HTMR

systemctl daemon-reload
systemctl enable --now ottvpn-health.timer

echo ""
echo "=== Setup Complete ==="
echo "WireGuard interface: wg0"
echo "Tunnel network: 10.66.0.0/24"
echo "DNS resolver: 0.0.0.0:5300 (Unbound)"
echo "Peer manager: 127.0.0.1:9123"
echo ""
echo "Server public key:"
cat /etc/wireguard/wg0.meta | grep public_key | cut -d= -f2