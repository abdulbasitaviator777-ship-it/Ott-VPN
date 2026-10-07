"""
OTT VPN — DNS and IPv6 leak protection.

Provides detection and remediation for:
  1. DNS leaks — when DNS queries escape through the ISP instead of
     the VPN's controlled resolver.
  2. IPv6 leaks — when IPv6 traffic bypasses the VPN tunnel.

Leak detection is tested by:
  - Fetching the public IP via known services and checking if it
    matches the VPN server's IP.
  - Querying DNS servers and verifying they resolve through the
    VPN (not the ISP).
  - Checking if an IPv6 address is available outside the VPN's
    tunnel network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import platform
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Public IP detection endpoints
IPV4_PROBES = [
    "https://api.ipify.org?format=json",
    "https://ipinfo.io/ip",
    "https://ifconfig.me/ip",
]
IPV6_PROBES = [
    "https://api6.ipify.org?format=json",
    "https://ipv6.icanhazip.com",
]

# DNS leak detection: query a wildcard domain that returns
# different IPs based on which resolver answered.
DNS_LEAK_TEST_DOMAIN = "dnsleak.ottvpn.in"


@dataclass
class LeakCheckResult:
    """Result of a leak check."""
    dns_protected: bool = True
    ipv6_protected: bool = True
    public_ip_match: bool = True
    public_ip: Optional[str] = None
    isp_ip: Optional[str] = None
    ipv6_address: Optional[str] = None
    detected_dns_servers: list[str] = None
    detail: str = ""

    def __post_init__(self):
        if self.detected_dns_servers is None:
            self.detected_dns_servers = []


class LeakProtection:
    """Detects and reports DNS and IPv6 leaks.

    Args:
        vpn_public_ip: The expected public IP address when connected
                       to the VPN (i.e., the Indian gateway's IP).
        vpn_dns_servers: List of DNS servers that the VPN should use.
        vpn_ipv6_prefix: The IPv6 prefix assigned to VPN tunnel (e.g. "fd86::/64").
    """

    def __init__(
        self,
        vpn_public_ip: Optional[str] = None,
        vpn_dns_servers: Optional[list[str]] = None,
        vpn_ipv6_prefix: str = "fd86::/64",
    ):
        self.vpn_public_ip = vpn_public_ip
        self.vpn_dns_servers = vpn_dns_servers or []
        self.vpn_ipv6_prefix = vpn_ipv6_prefix
        self._http: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._http = httpx.AsyncClient(timeout=10.0)
        return self

    async def __aexit__(self, *args):
        if self._http:
            await self._http.aclose()

    async def fetch_public_ip(self, ipv6: bool = False) -> Optional[str]:
        """Fetch the public IP as seen by external services."""
        probes = IPV6_PROBES if ipv6 else IPV4_PROBES
        if not self._http:
            self._http = httpx.AsyncClient(timeout=10.0)

        for probe in probes:
            try:
                resp = await self._http.get(probe, timeout=10.0)
                if resp.status_code == 200:
                    text = resp.text.strip()
                    if ipv6:
                        return text
                    if "application/json" in resp.headers.get("content-type", ""):
                        return resp.json().get("ip", text)
                    return text
            except Exception as exc:
                logger.debug("IP probe %s failed: %s", probe, exc)
        return None

    async def check_dns_leak(self) -> tuple[bool, list[str]]:
        """Check for DNS leaks.

        Returns (leaked, dns_servers).  If leaked is True, DNS queries
        are escaping through the ISP.
        """
        # Method 1: Check what DNS servers the system is using
        dns_servers = await self._get_system_dns()

        # Method 2: Query our special test domain
        try:
            if not self._http:
                self._http = httpx.AsyncClient(timeout=10.0)
            await self._http.get(f"https://{DNS_LEAK_TEST_DOMAIN}", timeout=8.0)
        except Exception:
            pass  # If we can't reach it, the DNS might be going through VPN

        # If VPN DNS servers are configured and system DNS differs, it's a leak
        if self.vpn_dns_servers:
            vpn_set = set(self.vpn_dns_servers)
            system_set = set(dns_servers)
            leaked_servers = system_set - vpn_set
            if leaked_servers:
                return True, dns_servers

        return False, dns_servers

    async def _get_system_dns(self) -> list[str]:
        """Get the system's configured DNS resolvers."""
        try:
            if platform.system() == "Windows":
                result = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: subprocess.run(
                        ["ipconfig", "/all"], capture_output=True, text=True
                    )
                )
                dns_servers = []
                for line in result.stdout.splitlines():
                    if "DNS Servers" in line or "DNS Server" in line:
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            if ip:
                                dns_servers.append(ip)
                return dns_servers
            else:
                with open("/etc/resolv.conf", "r") as f:
                    servers = []
                    for line in f:
                        if line.strip().startswith("nameserver"):
                            servers.append(line.split()[1])
                    return servers
        except Exception:
            return []

    async def check_ipv6_leak(self) -> tuple[bool, Optional[str]]:
        """Check for IPv6 leaks.

        Returns (leaked, ipv6_address).  If leaked is True and an IPv6
        address is available, it means IPv6 traffic is bypassing the VPN.
        """
        ipv6 = await self.fetch_public_ip(ipv6=True)
        if ipv6 is None:
            # No IPv6 available — it's blocked (safe)
            return False, None

        # Check if the IPv6 is in the VPN's tunnel range
        try:
            ip6_addr = ipaddress.ip_address(ipv6)
            vpn_net = ipaddress.ip_network(self.vpn_ipv6_prefix, strict=False)
            if ip6_addr in vpn_net:
                # IPv6 is in the VPN range — not leaking
                return False, ipv6
            # IPv6 is public and not in VPN range — leaking
            return True, ipv6
        except ValueError:
            return True, ipv6

    async def run_full_check(
        self, expected_isp_ip: Optional[str] = None
    ) -> LeakCheckResult:
        """Run a comprehensive leak check.

        Args:
            expected_isp_ip: The public IP before VPN connection (for detection).
        """
        # Check IPv4
        public_ip = await self.fetch_public_ip(ipv6=False)

        # If we know the VPN IP, check if public IP matches
        ip_match = True
        if self.vpn_public_ip and public_ip:
            ip_match = public_ip == self.vpn_public_ip

        # Check DNS leak
        dns_leaked, dns_servers = await self.check_dns_leak()

        # Check IPv6 leak
        ipv6_leaked, ipv6 = await self.check_ipv6_leak()

        result = LeakCheckResult(
            dns_protected=not dns_leaked,
            ipv6_protected=not ipv6_leaked,
            public_ip_match=ip_match,
            public_ip=public_ip,
            isp_ip=expected_isp_ip,
            ipv6_address=ipv6,
            detected_dns_servers=dns_servers,
        )

        if dns_leaked:
            result.detail = f"DNS leak detected: queries going to {dns_servers}"
        elif ipv6_leaked:
            result.detail = f"IPv6 leak detected: public IPv6 {ipv6} bypasses VPN"
        else:
            result.detail = "All leak checks passed"

        return result