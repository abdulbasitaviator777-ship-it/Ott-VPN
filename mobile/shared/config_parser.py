"""
OTT VPN — WireGuard configuration parser.

Parses .conf files produced by the backend into a structured object
that the tunnel manager can apply.  Never exposes server private keys
to the caller — only the client-side section is parsed.
"""
from __future__ import annotations

import base64
import configparser
import ipaddress
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class InterfaceSection:
    private_key: str
    addresses: list[str] = field(default_factory=list)
    dns: list[str] = field(default_factory=list)
    mtu: int = 1280
    preshared_key: str | None = None
    persistent_keepalive: int = 0


@dataclass
class PeerSection:
    public_key: str
    preshared_key: str | None = None
    endpoint: str | None = None
    allowed_ips: list[str] = field(default_factory=list)
    persistent_keepalive: int = 0
    pre_shared_key: str | None = None


@dataclass
class WireGuardConfig:
    interface: InterfaceSection
    peer: PeerSection
    raw: str = ""

    @property
    def tunnel_ips(self) -> list[str]:
        """Return tunnel IPs without CIDR prefix."""
        return [addr.split("/")[0] for addr in self.interface.addresses]

    @property
    def tunnel_ip4(self) -> str | None:
        for addr in self.interface.addresses:
            ip = addr.split("/")[0]
            try:
                ipaddress.IPv4Address(ip)
                return ip
            except ValueError:
                continue
        return None

    @property
    def tunnel_ip6(self) -> str | None:
        for addr in self.interface.addresses:
            ip = addr.split("/")[0]
            try:
                ipaddress.IPv6Address(ip)
                return ip
            except ValueError:
                continue
        return None

    @property
    def endpoint_host(self) -> str | None:
        if self.peer.endpoint:
            return self.peer.endpoint.split(":")[0]
        return None

    @property
    def endpoint_port(self) -> int | None:
        if self.peer.endpoint:
            parts = self.peer.endpoint.rsplit(":", 1)
            if len(parts) == 2:
                return int(parts[1])
        return None

    @property
    def all_allowed_ips(self) -> str:
        """Return AllowedIPs as a comma-separated string."""
        return ", ".join(self.peer.allowed_ips)


def parse_config(config_text: str) -> WireGuardConfig:
    """Parse a WireGuard .conf file into a structured object.

    Only parses the [Interface] (client) and [Peer] sections.
    Does NOT parse any server-side PrivateKey that might be present
    — if a server PrivateKey is found, it is ignored and logged.
    """
    parser = configparser.ConfigParser()
    parser.read_string(config_text)

    interface = InterfaceSection(private_key="", addresses=[], dns=[])
    peer = PeerSection(public_key="")

    if "Interface" in parser:
        iface = parser["Interface"]
        interface.private_key = iface.get("PrivateKey", "")
        addr_str = iface.get("Address", "")
        interface.addresses = [a.strip() for a in addr_str.split(",") if a.strip()]
        dns_str = iface.get("DNS", "")
        interface.dns = [d.strip() for d in dns_str.split(",") if d.strip()]
        interface.mtu = int(iface.get("MTU", "1280"))
        interface.preshared_key = iface.get("PresharedKey")
        interface.persistent_keepalive = int(iface.get("PersistentKeepalive", "0"))

    if "Peer" in parser:
        p = parser["Peer"]
        peer.public_key = p.get("PublicKey", "")
        peer.preshared_key = p.get("PresharedKey")
        peer.endpoint = p.get("Endpoint")
        allowed_str = p.get("AllowedIPs", "")
        peer.allowed_ips = [a.strip() for a in allowed_str.split(",") if a.strip()]
        peer.persistent_keepalive = int(p.get("PersistentKeepalive", "0"))
        peer.pre_shared_key = p.get("PresharedKey")

    return WireGuardConfig(interface=interface, peer=peer, raw=config_text)


def validate_config(config: WireGuardConfig) -> list[str]:
    """Validate a parsed WireGuard config.  Returns list of errors."""
    errors: list[str] = []

    if not config.interface.private_key:
        errors.append("Client PrivateKey is missing")
    if not config.peer.public_key:
        errors.append("Server PublicKey is missing")
    if not config.peer.endpoint:
        errors.append("Endpoint is missing")
    if not config.interface.addresses:
        errors.append("Tunnel Address is missing")
    if not config.interface.dns:
        errors.append("DNS server is missing")
    if not config.peer.allowed_ips:
        errors.append("AllowedIPs is missing")

    # Check allowed_ips includes full tunnel
    has_default4 = any(a == "0.0.0.0/0" for a in config.peer.allowed_ips)
    has_default6 = any(a == "::/0" for a in config.peer.allowed_ips)
    if not has_default4:
        errors.append("AllowedIPs does not include 0.0.0.0/0 (full tunnel)")

    return errors


def is_valid_wg_key(key: str) -> bool:
    """Check if a string is a valid WireGuard base64 key (32 bytes)."""
    try:
        raw = base64.b64decode(key, validate=True)
        return len(raw) == 32
    except Exception:
        return False


def mask_private_key(config_text: str) -> str:
    """Return config text with the PrivateKey masked (for logging)."""
    return re.sub(r"PrivateKey\s*=\s*(\S+)", r"PrivateKey = [REDACTED]", config_text)