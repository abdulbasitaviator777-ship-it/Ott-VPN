#!/usr/bin/env python3
"""
OTT VPN — CLI Client

A cross-platform command-line VPN client that:
  1. Authenticates with the backend API
  2. Fetches available Indian servers
  3. Requests a WireGuard config for the best server
  4. Applies the config to a WireGuard tunnel
  5. Monitors connection, leaks, and kill switch
  6. Handles automatic reconnection

Usage:
    python -m mobile.shared.cli login --email user@example.com
    python -m mobile.shared.cli connect
    python -m mobile.shared.cli status
    python -m mobile.shared.cli disconnect
    python -m mobile.shared.cli servers
    python -m mobile.shared.cli leaks
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from mobile.shared.vpn_api import VPNAPIClient, AuthTokens, ServerInfo
from mobile.shared.config_parser import parse_config, validate_config
from mobile.shared.tunnel import WireGuardTunnel, TunnelState
from mobile.shared.leak_protection import LeakProtection
from mobile.shared.kill_switch import KillSwitch, KillSwitchState

logger = logging.getLogger("ottvpn-cli")

CONFIG_DIR = Path.home() / ".config" / "ottvpn"
TOKEN_FILE = CONFIG_DIR / "tokens.json"
CONFIG_FILE = CONFIG_DIR / "wg0.conf"


class VPNConnectionManager:
    """Orchestrates the full VPN connection lifecycle.

    Handles: API auth → server selection → config fetch → tunnel up →
    leak check → kill switch → monitoring with auto-reconnect.
    """

    def __init__(self, api: VPNAPIClient):
        self.api = api
        self.tunnel: Optional[WireGuardTunnel] = None
        self.kill_switch: Optional[KillSwitch] = None
        self.leak_protector: Optional[LeakProtection] = None
        self._connected_server: Optional[ServerInfo] = None
        self._auto_reconnect_task: Optional[asyncio.Task] = None

    @property
    def is_connected(self) -> bool:
        return self.tunnel is not None and self.tunnel.state == TunnelState.UP

    async def authenticate(self, email: str, password: str) -> AuthTokens:
        tokens = await self.api.login(email, password)
        self._save_tokens(tokens)
        # Fetch server health to determine best endpoint
        health = await self.api.get_all_server_health("IN")
        return tokens

    async def connect(self, server_id: Optional[str] = None) -> bool:
        """Connect to a WireGuard server (auto-selects best if none specified)."""
        # 1. Get the best server
        if server_id is None:
            servers = await self.api.get_recommended(limit=1)
            if not servers:
                servers = await self.api.list_servers()
            if not servers:
                print("ERROR: No Indian servers available")
                return False
            server = servers[0]
        else:
            server = await self.api.get_server_detail(server_id)

        print(f"Connecting to {server.city}, {server.country} (latency: {server.latency_ms}ms)")

        # 2. Fetch WireGuard config
        config_data = await self.api.get_vpn_config(
            server_id=server.id, split_tunnel=False
        )

        # 3. Parse and validate config (never log the private key)
        config = parse_config(config_data.config)
        errors = validate_config(config)
        if errors:
            print(f"ERROR: Invalid config: {'; '.join(errors)}")
            return False

        # 4. Save config locally (for reconnection)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            f.write(config_data.config)
        os.chmod(CONFIG_FILE, 0o600)

        # 5. Bring up the tunnel
        self.tunnel = WireGuardTunnel(
            config=config,
            tunnel_interface="wg0",
        )

        print(f"Bringing up tunnel on {config.tunnel_ip4}...")
        state = await self.tunnel.up()
        if state != TunnelState.UP:
            print("ERROR: Failed to bring up tunnel")
            # Try fallback server
            print("Trying another Indian server...")
            await self._try_fallback()
            return self.is_connected

        # 6. Enable kill switch
        self.kill_switch = KillSwitch(
            tunnel_interface="wg0",
            tunnel_ip=config.tunnel_ip4,
            dns_servers=config.interface.dns,
        )
        await self.kill_switch.enable()

        # 7. Verify no leaks
        self.leak_protector = LeakProtection(
            vpn_public_ip=server.ipv4,
            vpn_dns_servers=config.interface.dns,
            vpn_ipv6_prefix=config.tunnel_ip6 or "fd86::/64",
        )
        async with self.leak_protector as lp:
            leak_result = await lp.run_full_check()

        if not leak_result.dns_protected:
            print("WARNING: DNS leak detected!")
        if not leak_result.ipv6_protected:
            print("WARNING: IPv6 leak detected!")

        self._connected_server = server
        print(f"Connected to {server.city} — IP: {leak_result.public_ip}")

        # 8. Start auto-reconnection monitor
        self._auto_reconnect_task = asyncio.create_task(self._monitor())

        return True

    async def _try_fallback(self):
        """Try connecting to the next-best server."""
        servers = await self.api.list_servers()
        for srv in servers:
            if srv.status != "healthy":
                continue
            if self._connected_server and srv.id == self._connected_server.id:
                continue
            try:
                print(f"Trying {srv.city}...")
                await self.connect(server_id=srv.id)
                return
            except Exception as exc:
                logger.warning("Fallback to %s failed: %s", srv.city, exc)
        print("ERROR: All Indian servers failed. Please try again later.")

    async def _monitor(self):
        """Monitor connection health and reconnect if needed."""
        while self.tunnel and self.tunnel.state == TunnelState.UP:
            await asyncio.sleep(30)
            if not await self.tunnel.is_connected():
                logger.warning("Tunnel handshake lost — attempting reconnect")
                await self.tunnel.down()
                await asyncio.sleep(2)
                await self.tunnel.up()

    async def disconnect(self):
        """Disconnect the VPN and restore normal traffic."""
        if self._auto_reconnect_task:
            self._auto_reconnect_task.cancel()
            self._auto_reconnect_task = None

        if self.kill_switch:
            await self.kill_switch.disable()

        if self.tunnel:
            await self.tunnel.down()
            self.tunnel = None

        self._connected_server = None
        print("Disconnected. Normal internet access restored.")

    async def status(self) -> dict:
        """Return current connection status."""
        stats = None
        if self.tunnel:
            stats = await self.tunnel.get_stats()

        return {
            "connected": self.is_connected,
            "server": self._connected_server.__dict__ if self._connected_server else None,
            "tunnel_state": self.tunnel.state.value if self.tunnel else "down",
            "kill_switch": self.kill_switch.state.value if self.kill_switch else "disabled",
            "tunnel_ip": self.tunnel.tunnel_ip if self.tunnel else None,
            "bytes_rx": stats.rx_bytes if stats else 0,
            "bytes_tx": stats.tx_bytes if stats else 0,
            "last_handshake": stats.latest_handshake if stats else None,
        }

    async def check_leaks(self) -> dict:
        """Run DNS and IPv6 leak checks."""
        if not self._connected_server:
            return {"error": "Not connected"}

        if not self.tunnel:
            return {"error": "No tunnel"}

        config = self.tunnel._config
        lp = LeakProtection(
            vpn_public_ip=self._connected_server.ipv4,
            vpn_dns_servers=config.interface.dns,
        )
        try:
            async with lp:
                result = await lp.run_full_check()
            return {
                "dns_leak": not result.dns_protected,
                "ipv6_leak": not result.ipv6_protected,
                "dns_leak_status": "PASS" if result.dns_protected else "FAIL",
                "ipv6_leak_status": "PASS" if result.ipv6_protected else "FAIL",
                "public_ip": result.public_ip,
                "details": result.detail,
            }
        finally:
            await lp.close()

    def _save_tokens(self, tokens: AuthTokens):
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(TOKEN_FILE, "w") as f:
            json.dump({"access_token": tokens.access_token, "refresh_token": tokens.refresh_token}, f)
        os.chmod(TOKEN_FILE, 0o600)

    def _load_tokens(self) -> Optional[AuthTokens]:
        if TOKEN_FILE.exists():
            with open(TOKEN_FILE) as f:
                data = json.load(f)
            return AuthTokens(
                access_token=data["access_token"],
                refresh_token=data.get("refresh_token"),
            )
        return None


async def main_cli():
    """CLI entry point for the OTT VPN client."""
    import argparse

    parser = argparse.ArgumentParser(description="OTT VPN Client")
    sub = parser.add_subparsers(dest="command")

    login_p = sub.add_parser("login")
    login_p.add_argument("--email", required=True)
    login_p.add_argument("--password", required=True)

    connect_p = sub.add_parser("connect")
    connect_p.add_argument("--server", help="Specific server ID")

    sub.add_parser("disconnect")
    sub.add_parser("status")
    sub.add_parser("servers")
    sub.add_parser("leaks")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    api = VPNAPIClient(base_url="http://localhost:8000")
    conn = VPNConnectionManager(api)

    if args.command == "login":
        tokens = await conn.authenticate(args.email, args.password)
        print(f"Logged in. Access token expires in {tokens.expires_in}s")

    elif args.command == "servers":
        servers = await api.list_servers()
        print(f"{'ID':<15} {'City':<15} {'Latency':<10} {'Load':<10} {'Status'}")
        print("-" * 60)
        for s in servers:
            print(f"{s.id:<15} {s.city:<15} {s.latency_ms or '--':<10} {s.load_percent or '--':<10} {s.status}")

    elif args.command == "connect":
        success = await conn.connect(server_id=args.server)
        if success:
            print("VPN connected!")
            # Keep running
            try:
                await asyncio.Event().wait()
            except (KeyboardInterrupt, asyncio.CancelledError):
                await conn.disconnect()
        else:
            sys.exit(1)

    elif args.command == "status":
        status = await conn.status()
        print(json.dumps(status, indent=2, default=str))

    elif args.command == "disconnect":
        await conn.disconnect()

    elif args.command == "leaks":
        result = await conn.check_leaks()
        print(json.dumps(result, indent=2))

    await api.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main_cli())