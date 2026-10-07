from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from enum import Enum


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    device_info: Optional[str] = None

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    device_info: Optional[str] = None


class TokenPayload(BaseModel):
    sub: str
    type: str = "access"
    exp: Optional[int] = None
    iat: Optional[int] = None


class LogoutRequest(BaseModel):
    refresh_token: Optional[str] = None


class ServerStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class OTTResult(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class ServerPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    city: str
    country: str
    region: Optional[str] = None
    latency_ms: Optional[float] = None
    load_percent: Optional[float] = None
    status: ServerStatus
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    ott_zee5: Optional[OTTResult] = None
    ott_jiohotstar: Optional[OTTResult] = None
    wireguard_port: Optional[int] = None


class ServerDetail(ServerPublic):
    hostname: Optional[str] = None
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    wireguard_pubkey: Optional[str] = None
    wireguard_net: Optional[str] = None
    wireguard_net6: Optional[str] = None
    protocol: Optional[str] = None
    capacity: Optional[int] = None
    current_peers: Optional[int] = None
    last_health_check: Optional[datetime] = None
    asn: Optional[int] = None
    dns_ok: Optional[bool] = None
    ipv6_ok: Optional[bool] = None
    ott_last_checked: Optional[datetime] = None
    preshared_key: Optional[bool] = None


class ServerListResponse(BaseModel):
    country: str = "IN"
    servers: list[ServerPublic]


class WireguardConfigResponse(BaseModel):
    server_id: str
    config: str
    expires_at: datetime


class VpnStatusResponse(BaseModel):
    connected: bool
    server: Optional[ServerPublic] = None
    tunnel_ip: Optional[str] = None
    public_ip: Optional[str] = None
    dns_protected: Optional[bool] = None
    ipv6_protected: Optional[bool] = None
    bytes_tx: Optional[int] = None
    bytes_rx: Optional[int] = None


class HealthCheckResponse(BaseModel):
    server_id: str
    status: str
    latency_ms: Optional[float] = None
    packet_loss: Optional[float] = None
    geolocated_in: bool
    dns_ok: bool
    ipv6_ok: bool
    ipv6_leak: bool
    dns_leak: bool
    detected_ip: Optional[str] = None
    detected_country: Optional[str] = None
    detected_asn: Optional[int] = None
    ott_zee5: Optional[str] = None
    ott_jiohotstar: Optional[str] = None
    timestamp: datetime


class ErrorResponse(BaseModel):
    detail: str
