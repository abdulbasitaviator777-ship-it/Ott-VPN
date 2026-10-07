#!/bin/bash
# OTT VPN — Firewall setup script for Indian WireGuard gateway
# Run as root on the gateway server
#
# Architecture:
#   - UFW for host firewall (default deny incoming, allow outgoing)
#   - iptables/nftables for WireGuard-specific rules
#   - Only UDP 51820 is exposed for WireGuard
#   - Peer manager listens on 127.0.0.1 only

set -euo pipefail

echo "=== OTT VPN Firewall Setup ==="

# --- 1. UFW host firewall ---
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 51820/udp
ufw allow from 127.0.0.1 to any port 9123
ufw --force enable

# --- 2. Kernel IP forwarding ---
cat > /etc/sysctl.d/99-ottvpn.conf << 'SYSCTL'
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv4.conf.all.src_validity_marker=0
SYSCTL
sysctl -p /etc/sysctl.d/99-ottvpn.conf

# --- 3. Kill switch: block client-to-client traffic on WireGuard ---
# Peers behind the same gateway cannot intercept each other
iptables -C FORWARD -i wg0 -o wg0 -j DROP 2>/dev/null || true
iptables -A FORWARD -i wg0 -o wg0 -j DROP
ip6tables -C FORWARD -i wg0 -o wg0 -j DROP 2>/dev/null || true
ip6tables -A FORWARD -i wg0 -o wg0 -j DROP

# --- 4. Rate limiting for abuse prevention ---
# Max 100 new WireGuard handshakes per minute per source IP
iptables -A INPUT -p udp --dport 51820 -m state --state NEW -m recent --set
iptables -A INPUT -p udp --dport 51820 -m state --state NEW -m recent --update --seconds 60 --hitcount 100 -j DROP

# --- 5. Default forward policy ---
iptables -P FORWARD DROP
ip6tables -P FORWARD DROP

echo "=== Firewall configured ==="
echo "WireGuard UDP 51820 allowed"
echo "Peer manager on 127.0.0.1:9123"
echo "SSH allowed"
echo "Default deny incoming, allow outgoing"