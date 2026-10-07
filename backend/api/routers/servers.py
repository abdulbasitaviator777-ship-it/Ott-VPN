from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.database import get_session
from backend.api.models import Server, ServerHealth, ServerStatus
from backend.api.schemas import (
    ServerListResponse,
    ServerDetail,
    ServerPublic,
    ServerStatus as SchemaStatus,
    OTTResult,
)

router = APIRouter(prefix="/api/servers", tags=["servers"])


@router.get("/", response_model=ServerListResponse)
async def list_servers(
    session: AsyncSession = Depends(get_session),
    country: str = Query(default="IN", max_length=2),
    city: Optional[str] = Query(default=None),
):
    """List all VPN servers in a given country (default India)."""
    stmt = select(Server).where(Server.country == country.upper())
    if city:
        stmt = stmt.where(Server.city == city)
    stmt = stmt.order_by(Server.id).options(selectinload(Server.health_records))
    result = await session.execute(stmt)
    servers = result.scalars().all()

    return ServerListResponse(
        country=country.upper(),
        servers=[_server_to_public(s) for s in servers],
    )


@router.get("/recommended", response_model=list[ServerPublic])
async def recommended_servers(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(default=5, ge=1, le=20),
):
    """Return the best-scoring Indian servers."""
    from backend.servers.selection import ServerSelector

    selector = ServerSelector(session)
    recommended = await selector.recommend(count=limit)
    return [_server_to_public(srv) for srv, _ in recommended]


@router.get("/{server_id}", response_model=ServerDetail)
async def get_server(
    server_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get detailed information for a single server."""
    result = await session.execute(
        select(Server).where(Server.id == server_id).options(
            selectinload(Server.health_records)
        )
    )
    server: Optional[Server] = result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return _server_to_detail(server)


def _server_to_public(server: Server) -> ServerPublic:
    return ServerPublic(
        id=server.id,
        city=server.city,
        country=server.country,
        region=server.region,
        latency_ms=_latest_health(server, "latency_ms"),
        load_percent=_latest_health(server, "load_percent"),
        status=SchemaStatus(server.status.value),
        latitude=float(server.latitude) if server.latitude else None,
        longitude=float(server.longitude) if server.longitude else None,
        ott_zee5=_ott_enum(server.ott_zee5),
        ott_jiohotstar=_ott_enum(server.ott_jiohotstar),
        wireguard_port=server.wireguard_port,
    )


def _server_to_detail(server: Server) -> ServerDetail:
    return ServerDetail(
        id=server.id,
        city=server.city,
        country=server.country,
        region=server.region,
        latency_ms=_latest_health(server, "latency_ms"),
        load_percent=_latest_health(server, "load_percent"),
        status=SchemaStatus(server.status.value),
        latitude=float(server.latitude) if server.latitude else None,
        longitude=float(server.longitude) if server.longitude else None,
        hostname=server.hostname,
        ipv4=str(server.ipv4) if server.ipv4 else None,
        ipv6=str(server.ipv6) if server.ipv6 else None,
        wireguard_pubkey=server.wireguard_pubkey,
        wireguard_net=server.wireguard_net,
        wireguard_net6=server.wireguard_net6,
        protocol=server.protocol,
        capacity=server.capacity,
        current_peers=server.current_peers,
        last_health_check=server.last_health_check,
        asn=server.asn,
        dns_ok=server.dns_ok,
        ipv6_ok=server.ipv6_ok,
        ott_zee5=_ott_enum(server.ott_zee5),
        ott_jiohotstar=_ott_enum(server.ott_jiohotstar),
        ott_last_checked=server.ott_last_checked,
        preshared_key=server.wireguard_preshared,
    )


def _latest_health(server: Server, field: str) -> Optional[float]:
    records = getattr(server, "health_records", []) or []
    if records:
        val = getattr(records[0], field, None)
        if val is not None:
            return float(val)
    return None


def _ott_enum(val: Optional[str]) -> Optional[OTTResult]:
    if val is None:
        return None
    try:
        return OTTResult(val)
    except ValueError:
        return OTTResult.UNKNOWN
