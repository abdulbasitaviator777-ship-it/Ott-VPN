#!/usr/bin/env python3
"""
OTT VPN — WireGuard Server Configuration Generator

Generates the server's own keypair, writes the [Interface] section,
and produces a peer-manager companion script used by the backend to
add/remove WireGuard peers on this gateway.

This script runs ON the Indian VPN gateway (Ubuntu 22.04 LTS).
It does NOT expose the server private key to clients — the private key
is written only to /etc/wireguard/ with 0600 permissions.

Usage:
    python generate_server_config.py --country IN --city Mumbai --port 51820
    python generate_server_config.py --country IN --city Mumbai --port 51820 --add-peer
"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import logging
import os
import sys
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ottvpn-wg")

WIREGUARD_CONF_DIR = "/etc/wireguard"
PEER_MANAGER_DIR = "/opt/ottvpn-peer-manager"


@dataclass
class ServerConfig:
    country: str
    city: str
    region: str
    tunnel_net_v4: str = "10.66.0.0/24"
    tunnel_net_v6: str = "fd86::/64"
    listen_port: int = 51820
    mtu: int = 1280
    interface_name: str = "wg0"
    endpoint_hostname: str = ""
    dns_resolver: str = "10.66.0.1"


def generate_server_keypair() -> tuple[str, str]:
    """Generate the server's Curve25519 key pair.

    Uses `wg genkey` when available (Linux).  Falls back to the
    cryptography library's X25519 on platforms without the wg binary.
    """
    import subprocess

    try:
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True).stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True, text=True, check=True).stdout.strip()
        return priv, pub
    except (FileNotFoundError, OSError):
        logger.info("wg binary not found, using cryptography fallback for key gen")
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, PublicFormat, NoEncryption,
        )
        private_obj = X25519PrivateKey.generate()
        private_bytes = private_obj.private_bytes(
            encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
        )
        public_bytes = private_obj.public_key().public_bytes(
            encoding=Encoding.Raw, format=PublicFormat.Raw
        )
        return base64.b64encode(private_bytes).decode("ascii"), base64.b64encode(public_bytes).decode("ascii")


def build_interface_config(cfg: ServerConfig, server_privkey: str) -> str:
    """Build the [Interface] section for the WireGuard server."""
    tunnel_addr_v4 = str(ipaddress.ip_network(cfg.tunnel_net_v4, strict=False).network_address + 1)
    tunnel_addr_v6 = str(ipaddress.ip_network(cfg.tunnel_net_v6, strict=False).network_address + 1)

    lines = [
        "# OTT VPN — WireGuard server configuration",
        f"# Gateway: {cfg.city}, {cfg.country}",
        f"# Generated: {__import__('datetime').datetime.utcnow().isoformat()}Z",
        "",
        "[Interface]",
        f"PrivateKey = {server_privkey}",
        f"Address = {tunnel_addr_v4}/{ipaddress.ip_network(cfg.tunnel_net_v4).prefixlen}, {tunnel_addr_v6}/{ipaddress.ip_network(cfg.tunnel_net_v6).prefixlen}",
        f"ListenPort = {cfg.listen_port}",
        f"MTU = {cfg.mtu}",
        f"PostUp = iptables -A FORWARD -i {cfg.interface_name} -j ACCEPT; iptables -A FORWARD -o {cfg.interface_name} -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -A FORWARD -i {cfg.interface_name} -j ACCEPT; ip6tables -A FORWARD -o {cfg.interface_name} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        f"PostDown = iptables -D FORWARD -i {cfg.interface_name} -j ACCEPT; iptables -D FORWARD -o {cfg.interface_name} -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -D FORWARD -i {cfg.interface_name} -j ACCEPT; ip6tables -D FORWARD -o {cfg.interface_name} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE",
        f"DNS = {cfg.dns_resolver}",
    ]
    return "\n".join(lines) + "\n"


def write_server_config(cfg: ServerConfig, server_privkey: str, server_pubkey: str) -> dict:
    """Write the WireGuard server config and register it as a systemd service."""
    os.makedirs(WIREGUARD_CONF_DIR, exist_ok=True)

    config_path = os.path.join(WIREGUARD_CONF_DIR, f"{cfg.interface_name}.conf")
    config_content = build_interface_config(cfg, server_privkey)

    with open(config_path, "w") as f:
        f.write(config_content)
    os.chmod(config_path, 0o600)

    # Write a metadata file (non-secret) for the backend
    meta_path = os.path.join(WIREGUARD_CONF_DIR, f"{cfg.interface_name}.meta")
    with open(meta_path, "w") as f:
        f.write(f"public_key={server_pubkey}\n")
        f.write(f"interface={cfg.interface_name}\n")
        f.write(f"tunnel_net_v4={cfg.tunnel_net_v4}\n")
        f.write(f"tunnel_net_v6={cfg.tunnel_net_v6}\n")
        f.write(f"listen_port={cfg.listen_port}\n")
        f.write(f"mtu={cfg.mtu}\n")
        f.write(f"country={cfg.country}\n")
        f.write(f"city={cfg.city}\n")
        f.write(f"region={cfg.region}\n")
        f.write(f"dns_resolver={cfg.dns_resolver}\n")
        f.write(f"endpoint_hostname={cfg.endpoint_hostname}\n")

    logger.info("Server config written to %s (permissions: 0600)", config_path)
    logger.info("Public key: %s", server_pubkey)
    return {
        "config_path": config_path,
        "meta_path": meta_path,
        "public_key": server_pubkey,
        "private_key": server_privkey,  # only for in-memory use, never returned over API
        "tunnel_addr_v4": str(ipaddress.ip_network(cfg.tunnel_net_v4, strict=False).network_address + 1),
        "tunnel_addr_v6": str(ipaddress.ip_network(cfg.tunnel_net_v6, strict=False).network_address + 1),
    }


def install_peer_manager(cfg: ServerConfig, server_pubkey: str) -> str:
    """Copy the standalone peer_manager.py script to the gateway.

    The script reads its runtime config (interface, tunnel nets, pubkey)
    from environment variables set via a systemd unit, so no
    code generation is needed.
    """
    import shutil

    os.makedirs(PEER_MANAGER_DIR, exist_ok=True)
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "peer_manager.py")
    dst = os.path.join(PEER_MANAGER_DIR, "peer_manager.py")
    shutil.copy2(src, dst)
    os.chmod(dst, 0o755)
    logger.info("Peer manager installed at %s", dst)
    return dst


def main():
    parser = argparse.ArgumentParser(description="OTT VPN WireGuard server config generator")
    parser.add_argument("--country", required=True, help="ISO country code (e.g. IN)")
    parser.add_argument("--city", required=True, help="City name (e.g. Mumbai)")
    parser.add_argument("--region", default="", help="Region/state")
    parser.add_argument("--port", type=int, default=51820)
    parser.add_argument("--tunnel-net-v4", default="10.66.0.0/24")
    parser.add_argument("--tunnel-net-v6", default="fd86::/64")
    parser.add_argument("--endpoint-hostname", default="")
    parser.add_argument("--interface", default="wg0")
    parser.add_argument("--install-peer-manager", action="store_true")
    args = parser.parse_args()

    cfg = ServerConfig(
        country=args.country,
        city=args.city,
        region=args.region,
        tunnel_net_v4=args.tunnel_net_v4,
        tunnel_net_v6=args.tunnel_net_v6,
        listen_port=args.port,
        interface_name=args.interface,
        endpoint_hostname=args.endpoint_hostname,
    )

    logger.info("Generating WireGuard server keys for %s, %s...", args.city, args.country)
    server_privkey, server_pubkey = generate_server_keypair()

    result = write_server_config(cfg, server_privkey, server_pubkey)

    if args.install_peer_manager:
        pm_path = install_peer_manager(cfg, server_pubkey)

        # Generate a random auth secret for the peer manager
        secret = os.urandom(32).hex()
        secret_path = os.path.join(WIREGUARD_CONF_DIR, "peer-manager.secret")
        with open(secret_path, "w") as f:
            f.write(secret)
        os.chmod(secret_path, 0o600)
        logger.info("Peer manager installed at %s", pm_path)
        logger.info("Peer manager secret: %s", secret_path)

    # Print server metadata (no private key) for the backend
    print("\n=== Server Metadata (safe to share with backend) ===")
    print(f"public_key={result['public_key']}")
    print(f"tunnel_net_v4={cfg.tunnel_net_v4}")
    print(f"tunnel_net_v6={cfg.tunnel_net_v6}")
    print(f"listen_port={cfg.listen_port}")
    print(f"interface={cfg.interface_name}")
    print(f"mtu={cfg.mtu}")
    print(f"dns_resolver={cfg.dns_resolver}")
    print(f"endpoint_hostname={cfg.endpoint_hostname}")
    print("\n=== IMPORTANT ===")
    print(f"Server private key written to: {result['config_path']} (chmod 600)")
    print("NEVER share this file or the private key with clients.")
    print("\nTo start WireGuard:")
    print(f"  sudo wg-quick up {cfg.interface_name}")
    if args.install_peer_manager:
        print(f"\nTo start peer manager:")
        print(f"  sudo python3 {pm_path} --port 9123 --secret $(cat {secret_path})")


if __name__ == "__main__":
    main()
