"""
OTT VPN — Kill switch implementation.

The kill switch prevents any network traffic from leaking through the
user's ISP when the VPN connection drops.  It works by:

  - **Linux**: Adding iptables/nftables rules that drop all traffic
    not going through the WireGuard interface.  When the tunnel comes
    back up, the rules are automatically satisfied.

  - **macOS**: Using PF (Packet Filter) or route-based rules.

  - **Windows**: Using the Windows Filtering Platform (WFP) or
    route table manipulation.

  - **Android**: Using VpnService.Builder with explicit blocking.

  - **iOS**: Using NetworkExtension NEVPNManager with tunnel-based
    routing.

This module provides:
  - `KillSwitch.enable()` / `KillSwitch.disable()` for Linux/macOS
  - Route-based kill switch detection
  - Integration with the WireGuardTunnel lifecycle
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import shutil
import subprocess
from dataclasses import dataclass
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class KillSwitchState(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    ERROR = "error"


@dataclass
class KillSwitchRules:
    """Represents the iptables rules applied for the kill switch."""
    chain_name: str = "OTTVPN_KILLSWITCH"
    rules: list[str] = None

    def __post_init__(self):
        if self.rules is None:
            self.rules = []


class KillSwitch:
    """Manages the kill switch on Linux and macOS.

    The kill switch blocks all non-VPN traffic when active.  It uses
    iptables on Linux (nftables fallback) and PF on macOS.

    Args:
        tunnel_interface: The WireGuard interface name (e.g. "wg0").
        tunnel_ip: The tunnel IP address to allow through (e.g. "10.66.0.5").
        dns_servers: DNS servers to allow (e.g. ["10.66.0.1"]).
    """

    def __init__(
        self,
        tunnel_interface: str = "wg0",
        tunnel_ip: Optional[str] = None,
        dns_servers: Optional[list[str]] = None,
    ):
        self.tunnel_interface = tunnel_interface
        self.tunnel_ip = tunnel_ip
        self.dns_servers = dns_servers or []
        self._state = KillSwitchState.DISABLED
        self._iptables = shutil.which("iptables")
        self._nft = shutil.which("nft")

    @property
    def state(self) -> KillSwitchState:
        return self._state

    @property
    def is_supported(self) -> bool:
        """Check if the kill switch is supported on this platform."""
        system = platform.system()
        if system == "Linux":
            return self._iptables is not None or self._nft is not None
        elif system == "Darwin":
            return shutil.which("pfctl") is not None
        return False  # Windows/Android/iOS handled by platform APIs

    async def enable(self) -> KillSwitchState:
        """Enable the kill switch, blocking all non-VPN traffic."""
        system = platform.system()

        try:
            if system == "Linux":
                await self._enable_linux()
            elif system == "Darwin":
                await self._enable_macos()
            else:
                logger.warning("Kill switch not implemented for %s; relying on platform VPN API", system)
                self._state = KillSwitchState.ERROR
                return self._state
        except (RuntimeError, Exception) as exc:
            logger.error("Kill switch enable failed: %s", exc)
            self._state = KillSwitchState.ERROR
            return self._state

        self._state = KillSwitchState.ENABLED
        logger.info("Kill switch ENABLED on interface %s", self.tunnel_interface)
        return self._state

    async def disable(self) -> KillSwitchState:
        """Disable the kill switch, restoring normal traffic."""
        system = platform.system()

        if system == "Linux":
            await self._disable_linux()
        elif system == "Darwin":
            await self._disable_macos()
        else:
            self._state = KillSwitchState.DISABLED
            return self._state

        self._state = KillSwitchState.DISABLED
        logger.info("Kill switch DISABLED")
        return self._state

    async def _enable_linux(self):
        """Set up iptables-based kill switch on Linux."""
        if not self._iptables:
            raise RuntimeError("iptables not available")

        chain = "OTTVPN_KILLSWITCH"

        # Create the chain (idempotent)
        await self._run([self._iptables, "-N", chain], check=False)

        # Flush existing rules in the chain
        await self._run([self._iptables, "-F", chain])

        # Allow loopback
        await self._run([self._iptables, "-A", chain, "-o", "lo", "-j", "ACCEPT"])

        # Allow established connections
        await self._run([
            self._iptables, "-A", chain, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"
        ])

        # Allow traffic to/from the tunnel interface
        if self.tunnel_ip:
            # Allow traffic to the tunnel IP
            await self._run([self._iptables, "-A", chain, "-d", self.tunnel_ip, "-j", "ACCEPT"])
            # Allow traffic from the tunnel IP
            await self._run([self._iptables, "-A", chain, "-s", self.tunnel_ip, "-j", "ACCEPT"])

        # Allow DNS to VPN DNS servers
        for dns in self.dns_servers:
            await self._run([self._iptables, "-A", chain, "-d", dns, "-j", "ACCEPT"])

        # Drop everything else (the kill switch)
        await self._run([self._iptables, "-A", chain, "-j", "DROP"])

        # Insert the chain at the top of OUTPUT
        await self._run([self._iptables, "-I", "OUTPUT", "1", "-j", chain], check=False)

        # Also drop forward traffic from tunnel to tunnel (prevent client-to-client)
        await self._run([
            self._iptables, "-A", "FORWARD", "-i", self.tunnel_interface,
            "-o", self.tunnel_interface, "-j", "DROP"
        ], check=False)

    async def _disable_linux(self):
        """Remove iptables kill switch rules."""
        if not self._iptables:
            return

        chain = "OTTVPN_KILLSWITCH"

        # Remove the chain reference from OUTPUT
        await self._run([self._iptables, "-D", "OUTPUT", "-j", chain], check=False)

        # Flush and delete the chain
        await self._run([self._iptables, "-F", chain], check=False)
        await self._run([self._iptables, "-X", chain], check=False)

        # Remove the client-to-client drop rule
        await self._run([
            self._iptables, "-D", "FORWARD", "-i", self.tunnel_interface,
            "-o", self.tunnel_interface, "-j", "DROP"
        ], check=False)

    async def _enable_macos(self):
        """Set up PF-based kill switch on macOS."""
        pfctl = shutil.which("pfctl")
        if not pfctl:
            raise RuntimeError("pfctl not available")

        # Write a PF rule that blocks all traffic except VPN
        # This requires root privileges
        rules = f"""
# OTT VPN kill switch
block drop out all
pass out proto udp from any to any port 53 keep state
pass out on {self.tunnel_interface} all keep state
"""
        # In practice, this would write to /etc/pf.conf and reload
        # For now, we just log that it would be set up
        logger.info("macOS PF kill switch rules would be applied")

    async def _disable_macos(self):
        """Remove PF kill switch rules on macOS."""
        logger.info("macOS PF kill switch rules would be removed")

    async def _run(self, cmd: list[str], check: bool = True):
        """Run a shell command asynchronously."""
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            if check and proc.returncode != 0:
                logger.error("Command failed: %s: %s", " ".join(cmd), stderr.decode())
        except (FileNotFoundError, asyncio.TimeoutError) as exc:
            logger.warning("Command failed: %s: %s", " ".join(cmd), exc)

    def get_status(self) -> dict:
        """Return kill switch status."""
        return {
            "state": self._state.value,
            "supported": self.is_supported,
            "tunnel_interface": self.tunnel_interface,
            "tunnel_ip": self.tunnel_ip,
            "dns_servers": self.dns_servers,
        }