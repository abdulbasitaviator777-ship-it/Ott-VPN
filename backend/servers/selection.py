from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.api.models import Server, ServerStatus, ServerHealth

logger = logging.getLogger(__name__)


class ServerSelector:
    """Intelligent server selection with health-based scoring."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_healthy_indian_servers(self) -> list[Server]:
        """Return all healthy servers geolocated in India."""
        stmt = (
            select(Server)
            .where(
                Server.country == "IN",
                Server.status == ServerStatus.HEALTHY,
            )
            .options(selectinload(Server.health_records))
        )
        result = await self.session.execute(stmt)
        return result.scalars().all()

    @staticmethod
    def compute_score(server: Server) -> float:
        """Compute a composite server score.  Lower is better.

        Score = latency_weight * latency_ms
              + loss_weight   * packet_loss
              + load_weight   * load_percent
              + penalty       * (availability issues)
        """
        latency = server_health_value(server, "latency_ms", default=0.0)
        loss = server_health_value(server, "packet_loss", default=0.0)
        load = server_health_value(server, "load_percent", default=0.0)

        # Weight factors (tunable) — latency prioritised for user experience
        latency_w = 0.55
        loss_w = 0.25
        load_w = 0.20

        # Normalise latency to a 0-100 scale relative to a 200 ms ceiling
        norm_latency = min(latency / 200.0 * 100, 100)
        norm_loss = min(loss, 100)
        norm_load = min(load, 100)

        score = (
            latency_w * norm_latency
            + loss_w * norm_loss
            + load_w * norm_load
        )

        # Penalties for not being fully healthy
        if server.status != ServerStatus.HEALTHY:
            score += 100  # heavily penalise degraded/offline

        # Penalise servers at capacity
        if server.capacity > 0:
            utilisation = server.current_peers / server.capacity
            if utilisation > 0.9:
                score += 50
            elif utilisation > 0.75:
                score += 20

        return round(score, 2)

    async def recommend(self, count: int = 1) -> list[tuple[Server, float]]:
        """Return the best `count` Indian servers with their scores."""
        servers = await self.get_healthy_indian_servers()
        scored = []
        for srv in servers:
            score = self.compute_score(srv)
            scored.append((srv, score))
        scored.sort(key=lambda x: x[1])
        return scored[:count]

    async def auto_select(self) -> Optional[Server]:
        """Select the single best available Indian server."""
        recommended = await self.recommend(count=1)
        if not recommended:
            return None
        return recommended[0][0]


def server_health_value(server: Server, field: str, default: float = 0.0) -> float:
    """Extract a health metric from the most recent health record, if available."""
    records = getattr(server, "health_records", []) or []
    if records:
        latest = records[0]
        val = getattr(latest, field, None)
        if val is not None:
            return float(val)
    return float(default)
