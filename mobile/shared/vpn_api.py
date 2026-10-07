"""
OTT VPN — Shared API client for the backend.

Provides authentication, server listing, config fetching, and status
checking via HTTPS.  Used by the mobile CLI client and test harnesses.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AuthTokens:
    access_token: str
    refresh_token: Optional[str] = None
    expires_in: int = 900
    token_type: str = "bearer"


@dataclass
class ServerInfo:
    id: str
    city: str
    country: str
    region: Optional[str] = None
    latency_ms: Optional[float] = None
    load_percent: Optional[float] = None
    status: str = "unknown"
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    wireguard_pubkey: Optional[str] = None
    wireguard_port: int = 51820
    wireguard_net: Optional[str] = None
    wireguard_net6: Optional[str] = None
    ott_zee5: Optional[str] = None
    ott_jiohotstar: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


@dataclass
class VpnStatus:
    connected: bool = False
    server: Optional[ServerInfo] = None
    tunnel_ip: Optional[str] = None
    public_ip: Optional[str] = None
    dns_protected: Optional[bool] = None
    ipv6_protected: Optional[bool] = None
    bytes_tx: Optional[int] = None
    bytes_rx: Optional[int] = None


@dataclass
class VpnConfig:
    server_id: str
    config: str
    expires_at: str


class VPNAPIClient:
    """Async HTTP client for the OTT VPN backend API."""

    def __init__(self, base_url: str = "https://api.ottvpn.example", verify_ssl: bool = True):
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30.0,
            verify=verify_ssl,
        )
        self._tokens: Optional[AuthTokens] = None

    async def close(self):
        await self._http.aclose()

    def set_tokens(self, tokens: AuthTokens):
        self._tokens = tokens
        self._http.headers["Authorization"] = f"Bearer {tokens.access_token}"

    async def register(self, email: str, password: str, device_info: Optional[str] = None) -> AuthTokens:
        resp = await self._http.post(
            "/api/auth/register",
            json={"email": email, "password": password, "device_info": device_info},
        )
        resp.raise_for_status()
        data = resp.json()
        login_resp = await self._http.post("/api/auth/login", json={"email": email, "password": password})
        login_resp.raise_for_status()
        login_data = login_resp.json()
        tokens = AuthTokens(
            access_token=data["access_token"],
            refresh_token=login_data.get("refresh_token"),
            expires_in=data["expires_in"],
        )
        self.set_tokens(tokens)
        return tokens

    async def login(self, email: str, password: str, device_info: Optional[str] = None) -> AuthTokens:
        resp = await self._http.post(
            "/api/auth/login",
            json={"email": email, "password": password, "device_info": device_info},
        )
        resp.raise_for_status()
        data = resp.json()
        tokens = AuthTokens(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            expires_in=data["expires_in"],
        )
        self.set_tokens(tokens)
        return tokens

    async def refresh(self) -> AuthTokens:
        if not self._tokens or not self._tokens.refresh_token:
            raise RuntimeError("No refresh token available")
        resp = await self._http.post("/api/auth/refresh", json={"refresh_token": self._tokens.refresh_token})
        if resp.status_code == 401:
            raise RuntimeError("Refresh token invalidated; please re-authenticate")
        resp.raise_for_status()
        data = resp.json()
        tokens = AuthTokens(
            access_token=data["access_token"],
            refresh_token=data["refresh_token"],
            expires_in=data["expires_in"],
        )
        self.set_tokens(tokens)
        return tokens

    async def logout(self, refresh_token: Optional[str] = None):
        payload = {"refresh_token": refresh_token} if refresh_token else {}
        await self._http.post("/api/auth/logout", json=payload)
        self._tokens = None
        self._http.headers.pop("Authorization", None)

    async def list_servers(self, country: str = "IN") -> list[ServerInfo]:
        resp = await self._http.get("/api/servers/", params={"country": country})
        resp.raise_for_status()
        data = resp.json()
        return [ServerInfo(**s) for s in data.get("servers", [])]

    async def get_recommended(self, limit: int = 5) -> list[ServerInfo]:
        resp = await self._http.get("/api/servers/recommended", params={"limit": limit})
        resp.raise_for_status()
        return [ServerInfo(**s) for s in resp.json()]

    async def get_server_detail(self, server_id: str) -> ServerInfo:
        resp = await self._http.get(f"/api/servers/{server_id}")
        resp.raise_for_status()
        return ServerInfo(**resp.json())

    async def get_vpn_config(self, server_id: Optional[str] = None, split_tunnel: bool = False) -> VpnConfig:
        params = {}
        if server_id:
            params["server_id"] = server_id
        if split_tunnel:
            params["split_tunnel"] = "true"
        resp = await self._http.post("/api/vpn/config", params=params or None)
        resp.raise_for_status()
        data = resp.json()
        return VpnConfig(
            server_id=data["server_id"],
            config=data["config"],
            expires_at=data["expires_at"],
        )

    async def revoke_config(self, peer_id: str) -> dict:
        resp = await self._http.post("/api/vpn/revoke", params={"peer_id": peer_id})
        resp.raise_for_status()
        return resp.json()

    async def get_vpn_status(self) -> VpnStatus:
        resp = await self._http.get("/api/vpn/status")
        resp.raise_for_status()
        data = resp.json()
        server = ServerInfo(**data["server"]) if data.get("server") else None
        return VpnStatus(
            connected=data.get("connected", False),
            server=server,
            tunnel_ip=data.get("tunnel_ip"),
            public_ip=data.get("public_ip"),
            dns_protected=data.get("dns_protected"),
            ipv6_protected=data.get("ipv6_protected"),
        )

    async def check_health(self) -> dict:
        resp = await self._http.get("/api/health/")
        return resp.json()

    async def get_server_health(self, server_id: str) -> dict:
        resp = await self._http.get(f"/api/health/servers/{server_id}")
        resp.raise_for_status()
        return resp.json()

    async def get_all_server_health(self, country: str = "IN") -> list[dict]:
        resp = await self._http.get("/api/health/servers", params={"country": country})
        resp.raise_for_status()
        return resp.json()