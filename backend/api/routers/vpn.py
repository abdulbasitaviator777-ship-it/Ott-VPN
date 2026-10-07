from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.database import get_session
from backend.api.deps import get_current_user
from backend.api.models import User, ClientPeer, Server, ServerStatus
from backend.api.schemas import (
    WireguardConfigResponse,
    VpnStatusResponse,
    ServerPublic,
    ServerStatus as SchemaStatus,
    OTTResult,
)
from backend.vpn.service import VpnService
from backend.api.config import settings

router = APIRouter(prefix="/api/vpn", tags=["vpn"])


@router.post("/config", response_model=WireguardConfigResponse)
async def generate_config(
    server_id: Optional[str] = None,
    split_tunnel: bool = False,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Generate (or regenerate) a WireGuard configuration for the user.

    If server_id is omitted, the best available Indian server is
    auto-selected.
    """
    service = VpnService(session)

    if server_id is None:
        from backend.servers.selection import ServerSelector

        selector = ServerSelector(session)
        server = await selector.auto_select()
        if server is None:
            raise HTTPException(
                status_code=503,
                detail="No healthy Indian servers available. Try again soon.",
            )
        server_id = server.id

    allowed_ips = "0.0.0.0/0, ::/0"
    if split_tunnel:
        allowed_ips = "10.66.0.0/24, fd86::/64"

    try:
        peer, config, expiry = await service.create_peer_config(
            user_id=str(user.id),
            server_id=server_id,
            allowed_ips=allowed_ips,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return WireguardConfigResponse(
        server_id=server_id,
        config=config,
        expires_at=expiry,
    )


@router.post("/revoke")
async def revoke_config(
    peer_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Revoke a previously issued WireGuard peer configuration."""
    service = VpnService(session)
    success = await service.revoke_peer(peer_id, str(user.id))
    if not success:
        raise HTTPException(status_code=404, detail="Peer configuration not found or not owned by user")
    return {"detail": "Peer configuration revoked"}


@router.get("/status", response_model=VpnStatusResponse)
async def vpn_status(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """Return the current VPN status for the authenticated user."""
    stmt = (
        select(ClientPeer)
        .where(ClientPeer.user_id == user.id, ClientPeer.revoked.is_(False))
        .order_by(ClientPeer.last_handshake.desc().nullslast())
    )
    result = await session.execute(stmt)
    peer: Optional[ClientPeer] = result.scalar_one_or_none()

    if peer is None:
        return VpnStatusResponse(connected=False)

    server_stmt = select(Server).where(Server.id == peer.server_id).options(
        selectinload(Server.health_records)
    )
    server_result = await session.execute(server_stmt)
    server: Optional[Server] = server_result.scalar_one_or_none()

    return VpnStatusResponse(
        connected=True,
        server=_server_to_public(server) if server else None,
        tunnel_ip=peer.address,
        public_ip=server.ipv4 if server else None,
        dns_protected=server.dns_ok,
        ipv6_protected=server.ipv6_ok,
    )


@router.get("/configs", response_model=list[dict])
async def list_peers(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    """List all active WireGuard peer configurations for the user."""
    service = VpnService(session)
    peers = await service.list_user_peers(str(user.id))
    return [
        {
            "peer_id": str(p.id),
            "server_id": p.server_id,
            "address": p.address,
            "address6": p.address6,
            "allowed_ips": p.allowed_ips,
            "expires_at": p.expires_at.isoformat() if p.expires_at else None,
            "last_handshake": p.last_handshake.isoformat() if p.last_handshake else None,
        }
        for p in peers
    ]


def _server_to_public(server: Server) -> ServerPublic:
    return ServerPublic(
        id=server.id,
        city=server.city,
        country=server.country,
        region=server.region,
        latency_ms=None,
        load_percent=None,
        status=SchemaStatus(server.status.value),
    )