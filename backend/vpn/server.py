"""
WireGuard server provisioning client.

Calls the peer-manager HTTP API running on each Indian gateway to
add/remove WireGuard peers and query stats.  This keeps the server's
private key on the gateway — the backend only manages peers via the
authenticated API.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional

import httpx

from backend.api.config import settings

logger = logging.getLogger(__name__)


class WireGuardServerClient:
    """HTTP client for the peer-manager API on a WireGuard gateway."""

    def __init__(self, host: str, port: int = 9123, secret: str = ""):
        self.base_url = f"http://{host}:{port}"
        self.secret = secret
        self._http: Optional[httpx.AsyncClient] = None

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=10.0)
        return self._http

    @property
    def auth_token(self) -> str:
        return hashlib.sha256(self.secret.encode()).hexdigest()

    def _headers(self) -> dict[str, str]:
        return {"X-Auth-Token": self.auth_token, "Content-Type": "application/json"}

    async def add_peer(
        self,
        public_key: str,
        preshared_key: Optional[str],
        allowed_ips: str,
        tunnel_ip: str,
        tunnel_ip6: Optional[str] = None,
    ) -> bool:
        """Register a client peer on the WireGuard gateway."""
        payload = {
            "public_key": public_key,
            "preshared_key": preshared_key,
            "allowed_ips": allowed_ips,
            "tunnel_ip": tunnel_ip,
            "tunnel_ip6": tunnel_ip6,
        }
        try:
            resp = await self.http.post(f"{self.base_url}/peers", json=payload, headers=self._headers())
            if resp.status_code == 201:
                logger.info("Peer %s registered on gateway", public_key[:16])
                return True
            logger.warning("Peer registration failed: %d %s", resp.status_code, resp.text)
            return False
        except httpx.RequestError as exc:
            logger.error("Failed to contact gateway %s: %s", self.base_url, exc)
            return False

    async def remove_peer(self, public_key: str) -> bool:
        """Remove a client peer from the WireGuard gateway."""
        try:
            resp = await self.http.delete(
                f"{self.base_url}/peers/{public_key}",
                headers=self._headers(),
            )
            return resp.status_code == 200
        except httpx.RequestError as exc:
            logger.error("Failed to contact gateway %s: %s", self.base_url, exc)
            return False

    async def get_server_info(self) -> dict:
        """Return server metadata (interface, public key, tunnel nets)."""
        try:
            resp = await self.http.get(f"{self.base_url}/server-info", headers=self._headers())
            return resp.json()
        except httpx.RequestError as exc:
            logger.error("Failed to contact gateway %s: %s", self.base_url, exc)
            return {}

    async def get_stats(self) -> dict:
        """Return WireGuard interface stats from the gateway."""
        try:
            resp = await self.http.get(f"{self.base_url}/stats", headers=self._headers())
            return resp.json()
        except httpx.RequestError as exc:
            logger.error("Failed to contact gateway %s: %s", self.base_url, exc)
            return {}

    async def close(self):
        if self._http is not None:
            await self._http.aclose()
            self._http = None


def create_server_client_from_server(server) -> WireGuardServerClient:
    """Create a WireGuardServerClient from a Server model instance.

    Expects the server to have a `wireguard_port` and `hostname`/`ipv4`.
    The peer-manager secret is expected to be in the server's metadata
    or environment.
    """
    host = server.hostname or str(server.ipv4)
    secret = getattr(server, "peer_manager_secret", "") or ""
    return WireGuardServerClient(host=host, port=server.wireguard_port, secret=secret)
