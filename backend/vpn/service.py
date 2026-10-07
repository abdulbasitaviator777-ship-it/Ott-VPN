from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.config import settings
from backend.api.models import ClientPeer, Server, ServerStatus
from backend.vpn.wireguard import (
    build_wireguard_config,
    generate_keypair,
    generate_preshared_key,
    allocate_tunnel_ip,
    allocate_tunnel_ip6,
)

logger = logging.getLogger(__name__)


class VpnService:
    """High-level service for WireGuard peer registration and config issuance."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create_peer_config(
        self,
        user_id: str,
        server_id: str,
        allowed_ips: Optional[str] = None,
    ) -> tuple[ClientPeer, str, datetime]:
        """Register a new WireGuard peer on a server and return its config.

        Returns (ClientPeer model, config_text, expiry_datetime).
        """
        server = await self._get_server(server_id)
        if server is None:
            raise ValueError(f"Server '{server_id}' not found")
        if server.status == ServerStatus.OFFLINE:
            raise ValueError(f"Server '{server_id}' is offline")

        used_ips_v4: set[str] = await self._used_tunnel_ips(server_id, ipv4=True)
        used_ips_v6: set[str] = await self._used_tunnel_ips(server_id, ipv4=False)

        tunnel_ip = allocate_tunnel_ip(settings.wg_default_address_pool, used_ips_v4)
        tunnel_ip_cidr = self._add_prefix(tunnel_ip, settings.wg_default_address_pool)

        tunnel_ip6 = None
        tunnel_ip6_cidr = None
        if server.wireguard_net6:
            ip6 = allocate_tunnel_ip6(settings.wg_default_address_pool6, used_ips_v6)
            tunnel_ip6 = ip6
            tunnel_ip6_cidr = self._add_prefix(ip6, settings.wg_default_address_pool6)

        client_privkey, client_pubkey = generate_keypair()
        psk = generate_preshared_key()

        expiry = datetime.now(timezone.utc) + timedelta(hours=settings.client_config_expiry_hours)

        peer = ClientPeer(
            user_id=__import__("uuid").UUID(user_id) if isinstance(user_id, str) else user_id,
            server_id=server_id,
            public_key=client_pubkey,
            preshared_key=psk,
            address=tunnel_ip_cidr,
            address6=tunnel_ip6_cidr,
            allowed_ips=allowed_ips or "0.0.0.0/0, ::/0",
            expires_at=expiry,
            revoked=False,
        )
        self.session.add(peer)
        await self.session.commit()
        await self.session.refresh(peer)

        dns_servers = self._build_dns_list(server)
        config = build_wireguard_config(
            client_private_key=client_privkey,
            server_public_key=server.wireguard_pubkey,
            server_endpoint=server.hostname or str(server.ipv4),
            server_port=server.wireguard_port,
            tunnel_ip=tunnel_ip_cidr,
            tunnel_ip6=tunnel_ip6_cidr,
            preshared_key=psk,
            allowed_ips=peer.allowed_ips,
            persistent_keepalive=settings.wg_persistent_keepalive,
            mtu=settings.wg_mtu,
            dns_servers=dns_servers,
        )
        return peer, config, expiry

    async def revoke_peer(self, peer_id: str, user_id: str) -> bool:
        """Revoke a client peer by id (only the owning user may do this)."""
        from uuid import UUID

        stmt = select(ClientPeer).where(ClientPeer.id == UUID(peer_id))
        result = await self.session.execute(stmt)
        peer: Optional[ClientPeer] = result.scalar_one_or_none()
        if peer is None:
            return False
        if str(peer.user_id) != user_id:
            return False
        peer.revoked = True
        await self.session.commit()
        return True

    async def list_user_peers(self, user_id: str):
        from uuid import UUID

        stmt = select(ClientPeer).where(
            ClientPeer.user_id == UUID(user_id),
            ClientPeer.revoked.is_(False),
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def rotate_peer_keys(self, peer_id: str, server_id: str) -> tuple[ClientPeer, str, datetime]:
        """Rotate a peer's keys (called periodically for security)."""
        from uuid import UUID

        stmt = select(ClientPeer).where(ClientPeer.id == UUID(peer_id), ClientPeer.server_id == server_id)
        result = await self.session.execute(stmt)
        peer: Optional[ClientPeer] = result.scalar_one_or_none()
        if peer is None or peer.revoked:
            raise ValueError("Peer not found or revoked")

        new_privkey, new_pubkey = generate_keypair()
        peer.public_key = new_pubkey
        if not peer.preshared_key:
            peer.preshared_key = generate_preshared_key()

        server = await self._get_server(server_id)
        dns_servers = self._build_dns_list(server)
        new_config = build_wireguard_config(
            client_private_key=new_privkey,
            server_public_key=server.wireguard_pubkey,
            server_endpoint=server.hostname or str(server.ipv4),
            server_port=server.wireguard_port,
            tunnel_ip=peer.address,
            tunnel_ip6=peer.address6,
            preshared_key=peer.preshared_key,
            allowed_ips=peer.allowed_ips,
            persistent_keepalive=settings.wg_persistent_keepalive,
            mtu=settings.wg_mtu,
            dns_servers=dns_servers,
        )
        await self.session.commit()
        await self.session.refresh(peer)
        return peer, new_config, datetime.now(timezone.utc)

    async def _get_server(self, server_id: str) -> Optional[Server]:
        stmt = select(Server).where(Server.id == server_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _used_tunnel_ips(self, server_id: str, ipv4: bool) -> set[str]:
        """Return the set of assigned tunnel IPs already in use for a server."""
        col = ClientPeer.address if ipv4 else ClientPeer.address6
        stmt = select(col).where(
            ClientPeer.server_id == server_id,
            ClientPeer.revoked.is_(False),
        )
        result = await self.session.execute(stmt)
        used: set[str] = set()
        for row in result.scalars():
            if row is None:
                continue
            for addr in str(row).split(","):
                ip_part = addr.strip().split("/")[0]
                used.add(ip_part)
        return used

    @staticmethod
    def _add_prefix(ip: str, cidr_pool: str) -> str:
        """Append the correct prefix length from the pool."""
        net = ipaddress.ip_network(cidr_pool, strict=False)
        return f"{ip}/{net.prefixlen}"

    @staticmethod
    def _build_dns_list(server: Server) -> list[str]:
        """Build DNS server list — the gateway's tunnel DNS + controlled resolver."""
        dns = []
        if server.wireguard_net:
            net = ipaddress.ip_network(server.wireguard_net, strict=False)
            dns.append(str(net.network_address + 1))
        if server.wireguard_net6:
            net6 = ipaddress.ip_network(server.wireguard_net6, strict=False)
            dns.append(str(net6.network_address + 1))
        if not dns:
            dns = ["10.66.0.1"]
        return dns
