"""
OTT VPN — WireGuard tunnel manager.

Manages the WireGuard interface lifecycle: bringing up the TUN interface,
applying configuration, reading stats, and tearing down.

Platform support:
  - Linux: uses `wg-quick` and `wg` userspace tools
  - macOS: uses `wireguard-go` in userspace mode
  - Fallback: can parse config and validate without applying

This module does NOT contain or expose server private keys.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from mobile.shared.config_parser import WireGuardConfig, parse_config, validate_config

logger = logging.getLogger(__name__)


class TunnelState(Enum):
    DOWN = "down"
    BRINGING_UP = "bringing_up"
    UP = "up"
    BRINGING_DOWN = "bringing_down"
    ERROR = "error"


@dataclass
class TunnelStats:
    latest_handshake: Optional[float] = None
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    peer_count: int = 0


class WireGuardTunnel:
    """Manages a WireGuard tunnel interface.

    Args:
        config: Either a WireGuardConfig object or a path to a .conf file.
        interface_name: The TUN interface name (default: ottvpn0).
        wg_bin: Path to the `wg` binary (auto-detected).
        wg_quick_bin: Path to `wg-quick` (auto-detected).
    """

    def __init__(
        self,
        config: WireGuardConfig | str,
        interface_name: str = "ottvpn0",
        wg_bin: Optional[str] = None,
        wg_quick_bin: Optional[str] = None,
    ):
        self.interface_name = interface_name
        self.wg_bin = wg_bin or shutil.which("wg")
        self.wg_quick_bin = wg_quick_bin or shutil.which("wg-quick")
        self._state = TunnelState.DOWN
        self._config: Optional[WireGuardConfig] = None

        if isinstance(config, WireGuardConfig):
            self._config = config
        else:
            with open(config, "r") as f:
                self._config = parse_config(f.read())

        if not self._config:
            raise ValueError("No configuration provided")

        errors = validate_config(self._config)
        if errors:
            raise ValueError(f"Invalid WireGuard config: {'; '.join(errors)}")

    @property
    def state(self) -> TunnelState:
        return self._state

    @property
    def tunnel_ip(self) -> Optional[str]:
        return self._config.tunnel_ip4 if self._config else None

    @property
    def server_ip(self) -> Optional[str]:
        return self.peer.endpoint_host if self._config and self._config.peer.endpoint else None

    async def up(self) -> TunnelState:
        """Bring up the WireGuard tunnel."""
        self._state = TunnelState.BRINGING_UP

        if not self.wg_bin:
            logger.warning("wg binary not found — tunnel management limited to config validation")
            self._state = TunnelState.ERROR
            return self._state

        # Write the config to a temp file for wg-quick
        config_path = f"/tmp/ottvpn-{self.interface_name}.conf"
        with open(config_path, "w") as f:
            f.write(self._config.raw)
        os.chmod(config_path, 0o600)

        try:
            proc = await asyncio.create_subprocess_exec(
                self.wg_quick_bin or "wg-quick",
                "up",
                config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if proc.returncode != 0:
                logger.error("wg-quick failed: %s", stderr.decode())
                self._state = TunnelState.ERROR
                return self._state
        except (FileNotFoundError, asyncio.TimeoutError) as exc:
            logger.error("Failed to bring up tunnel: %s", exc)
            self._state = TunnelState.ERROR
            return self._state

        self._state = TunnelState.UP
        logger.info("Tunnel %s is UP (tunnel IP: %s)", self.interface_name, self.tunnel_ip)
        return self._state

    async def down(self) -> TunnelState:
        """Tear down the WireGuard tunnel and remove routes."""
        self._state = TunnelState.BRINGING_DOWN

        if not self.wg_bin:
            self._state = TunnelState.ERROR
            return self._state

        config_path = f"/tmp/ottvpn-{self.interface_name}.conf"
        try:
            proc = await asyncio.create_subprocess_exec(
                self.wg_quick_bin or "wg-quick",
                "down",
                config_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=10.0)
        except (FileNotFoundError, asyncio.TimeoutError) as exc:
            logger.error("Failed to tear down tunnel: %s", exc)

        # Clean up the kill switch
        await self._remove_kill_switch()
        self._state = TunnelState.DOWN
        return self._state

    async def get_stats(self) -> TunnelStats:
        """Read WireGuard peer statistics."""
        if not self.wg_bin or self._state != TunnelState.UP:
            return TunnelStats()

        try:
            proc = await asyncio.create_subprocess_exec(
                self.wg_bin, "show", "wg0",
                "latest-handshakes", "transfer", "latest-handshake",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            output = stdout.decode()
            stats = TunnelStats()

            for line in output.splitlines():
                if "latest-handshake" in line:
                    # Parse: interface: ... or peer: ... with handshake
                    pass
                if "transfer" in line:
                    pass

            # Simpler: use wg show wg0 transfer
            proc = await asyncio.create_subprocess_exec(
                self.wg_bin, "show", "wg0", "transfer",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            for line in stdout.decode().splitlines():
                if "tx bytes" in line:
                    stats.tx_bytes = int(line.split("=")[1].strip())
                elif "rx bytes" in line:
                    stats.rx_bytes = int(line.split("=")[1].strip())

            # Latest handshake
            proc = await asyncio.create_subprocess_exec(
                self.wg_bin, "show", "wg0", "latest-handshake",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5.0)
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        ts = int(line.split("\t")[-1])
                        if ts > 0:
                            stats.latest_handshake = time.time() - ts
                    except (ValueError, IndexError):
                        pass

            return stats
        except (FileNotFoundError, asyncio.TimeoutError, Exception) as exc:
            logger.warning("Failed to get WireGuard stats: %s", exc)
            return TunnelStats()

    async def is_connected(self) -> bool:
        """Check if the tunnel has a recent handshake (within 180s)."""
        if self._state != TunnelState.UP:
            return False
        stats = await self.get_stats()
        if stats.latest_handshake is None:
            return False
        # Handshake within 2.5 minutes means connected
        return stats.latest_handshake < 180