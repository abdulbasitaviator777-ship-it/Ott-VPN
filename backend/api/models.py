import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Enum,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    DateTime,
    JSON,
    func,
    UUID as SA_UUID,
)
from sqlalchemy.orm import mapped_column, Mapped, relationship

from backend.api.database import Base


def uuid_gen() -> uuid.UUID:
    return uuid.uuid4()


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), primary_key=True, default=uuid_gen)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.USER)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("plans.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    peers: Mapped[list["ClientPeer"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class Plan(Base):
    __tablename__ = "plans"

    id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), primary_key=True, default=uuid_gen)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    max_devices: Mapped[int] = mapped_column(Integer, default=1)
    price_cents: Mapped[int] = mapped_column(Integer, default=0)
    sort_order: Mapped[int] = mapped_column(Integer, default=0)

    users: Mapped[list["User"]] = relationship(back_populates="plan", cascade="all, delete-orphan")


User.plan = relationship("Plan", back_populates="users")


class TokenStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class RefreshToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), primary_key=True, default=uuid_gen)
    user_id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("api_tokens.id"), nullable=True)
    status: Mapped[TokenStatus] = mapped_column(Enum(TokenStatus), default=TokenStatus.ACTIVE)
    device_info: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")
    replacer: Mapped["RefreshToken | None"] = relationship(remote_side=[id])


class ServerStatus(str, enum.Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    OFFLINE = "offline"


class Server(Base):
    __tablename__ = "servers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    country: Mapped[str] = mapped_column(String(2), nullable=False, index=True)
    city: Mapped[str] = mapped_column(String(128), nullable=False)
    region: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Numeric(10, 8), nullable=True)
    longitude: Mapped[float | None] = mapped_column(Numeric(11, 8), nullable=True)
    ipv4: Mapped[str | None] = mapped_column(String(45), nullable=True)
    ipv6: Mapped[str | None] = mapped_column(String(45), nullable=True)
    wireguard_pubkey: Mapped[str | None] = mapped_column(Text, nullable=True)
    wireguard_port: Mapped[int] = mapped_column(Integer, default=51820)
    wireguard_net: Mapped[str | None] = mapped_column(String(64), nullable=True)
    wireguard_net6: Mapped[str | None] = mapped_column(String(64), nullable=True)
    wireguard_preshared: Mapped[bool] = mapped_column(Boolean, default=False)
    protocol: Mapped[str] = mapped_column(String(32), default="wireguard")
    status: Mapped[ServerStatus] = mapped_column(Enum(ServerStatus), default=ServerStatus.OFFLINE)
    capacity: Mapped[int] = mapped_column(Integer, default=100)
    current_peers: Mapped[int] = mapped_column(Integer, default=0)
    last_health_check: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dns_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ipv6_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    ott_zee5: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ott_jiohotstar: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ott_last_checked: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    health_records: Mapped[list["ServerHealth"]] = relationship(back_populates="server", cascade="all, delete-orphan")
    peers: Mapped[list["ClientPeer"]] = relationship(back_populates="server", cascade="all, delete-orphan")


class OTTResult(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"


class ServerHealth(Base):
    __tablename__ = "server_health"

    id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), primary_key=True, default=uuid_gen)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), nullable=False, index=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    latency_ms: Mapped[float | None] = mapped_column(Numeric(10, 3), nullable=True)
    packet_loss: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    load_percent: Mapped[float | None] = mapped_column(Numeric(5, 2), nullable=True)
    dns_leak: Mapped[bool] = mapped_column(Boolean, default=False)
    ipv6_leak: Mapped[bool] = mapped_column(Boolean, default=False)
    geolocated_in: Mapped[bool] = mapped_column(Boolean, default=False)
    ip_version: Mapped[str | None] = mapped_column(String(8), nullable=True)
    detected_country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    detected_asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    detail: Mapped[str | None] = mapped_column(JSON(), nullable=True)

    server: Mapped["Server"] = relationship(back_populates="health_records")


class ClientPeer(Base):
    __tablename__ = "client_peers"

    id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), primary_key=True, default=uuid_gen)
    user_id: Mapped[uuid.UUID] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    server_id: Mapped[str] = mapped_column(ForeignKey("servers.id"), nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    preshared_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    address6: Mapped[str | None] = mapped_column(String(64), nullable=True)
    allowed_ips: Mapped[str] = mapped_column(Text, default="0.0.0.0/0, ::/0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_handshake: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    config_serialized: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship(back_populates="peers")
    server: Mapped["Server"] = relationship(back_populates="peers")