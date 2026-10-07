from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.database import get_session
from backend.api.deps import get_current_user, get_admin_user
from backend.api.models import User, Server, ServerHealth, ServerStatus
from backend.api.schemas import HealthCheckResponse

router = APIRouter(prefix="/api/health", tags=["health"])


@router.get("/", response_model=dict)
async def health_root():
    """Public health endpoint for the API itself."""
    return {"status": "ok", "service": "ott-vpn-backend"}


@router.get("/servers", response_model=list[HealthCheckResponse])
async def server_health_overview(
    session: AsyncSession = Depends(get_session),
    country: str = "IN",
):
    """Return health summary for all servers."""
    stmt = select(Server).where(Server.country == country.upper())
    result = await session.execute(stmt)
    servers = result.scalars().all()

    responses = []
    for srv in servers:
        latest = _latest_health_record(srv)
        responses.append(HealthCheckResponse(
            server_id=srv.id,
            status=srv.status.value,
            latency_ms=_get(latest, "latency_ms"),
            packet_loss=_get(latest, "packet_loss"),
            geolocated_in=_get(latest, "geolocated_in", default=True),
            dns_ok=srv.dns_ok or False,
            ipv6_ok=srv.ipv6_ok or False,
            ipv6_leak=_get(latest, "ipv6_leak", default=False),
            dns_leak=_get(latest, "dns_leak", default=False),
            detected_ip=str(srv.ipv4) if srv.ipv4 else None,
            detected_country=srv.country,
            detected_asn=srv.asn,
            ott_zee5=srv.ott_zee5 or "unknown",
            ott_jiohotstar=srv.ott_jiohotstar or "unknown",
            timestamp=_get(latest, "checked_at") or srv.last_health_check or None,
            detail=_get(latest, "detail", default={}),
        ))
    return responses


@router.get("/servers/{server_id}", response_model=HealthCheckResponse)
async def server_health_detail(
    server_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Run an on-demand health check for a specific server.

    Requires admin privileges.
    """
    user = Depends(get_admin_user)
    stmt = select(Server).where(Server.id == server_id)
    result = await session.execute(stmt)
    server: Optional[Server] = result.scalar_one_or_none()
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")

    from backend.health.checks import HealthChecker

    checker = HealthChecker()
    host = server.hostname or str(server.ipv4)
    port = server.wireguard_port
    raw = await checker.run_full_check(server_id, host, port)
    await checker.http.aclose()

    return HealthCheckResponse(
        server_id=raw.server_id,
        status=raw.status,
        latency_ms=raw.latency_ms,
        packet_loss=raw.packet_loss,
        geolocated_in=raw.geolocated_in,
        dns_ok=raw.dns_ok,
        ipv6_ok=raw.ipv6_ok,
        ipv6_leak=raw.ipv6_leak,
        dns_leak=raw.dns_leak,
        detected_ip=raw.detected_ip,
        detected_country=raw.detected_country,
        detected_asn=raw.detected_asn,
        ott_zee5=raw.ott_zee5 or "unknown",
        ott_jiohotstar=raw.ott_jiohotstar or "unknown",
        timestamp=raw.timestamp,
        detail=raw.detail,
    )


def _latest_health_record(server: Server) -> Optional[ServerHealth]:
    records = getattr(server, "health_records", []) or []
    return records[0] if records else None


def _get(obj, attr: str, default=None):
    if obj is None:
        return default
    return getattr(obj, attr, default)