import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, insert
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.database import get_session
from backend.api.models import User, RefreshToken, Plan, TokenStatus
from backend.api.schemas import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    RefreshResponse,
    LogoutRequest,
)
from backend.auth.passwords import hash_password, verify_password, TokenHasher, RefreshTokenManager
from backend.auth.jwt import create_access_token, create_refresh_token, verify_token, ensure_aware
from backend.api.deps import RateLimiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    payload: RegisterRequest,
    session: AsyncSession = Depends(get_session),
):
    """Register a new user account and immediately issue tokens."""
    stmt = select(User).where(User.email == payload.email.lower())
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(email=payload.email.lower(), password_hash=hash_password(payload.password))
    session.add(user)
    await session.commit()
    await session.refresh(user)

    access_token = create_access_token(str(user.id))
    refresh_value, expires_at = create_refresh_token(str(user.id))
    token_hash = TokenHasher.hash_token(refresh_value)
    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        device_info=payload.device_info or "web",
    )
    session.add(db_token)
    await session.commit()

    return TokenResponse(
        access_token=access_token,
        expires_in=15 * 60,
    )


@router.post("/login", response_model=RefreshResponse)
async def login(
    payload: LoginRequest,
    session: AsyncSession = Depends(get_session),
):
    """Authenticate a user and issue access + refresh tokens.

    Implements refresh-token rotation: each login revokes prior active
    tokens for the same device and issues a new refresh token.
    """
    stmt = select(User).where(User.email == payload.email.lower())
    result = await session.execute(stmt)
    user: Optional[User] = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user.last_login_at = datetime.now(timezone.utc)
    await session.commit()

    access_token = create_access_token(str(user.id))
    refresh_value, expires_at = create_refresh_token(str(user.id))
    token_hash = TokenHasher.hash_token(refresh_value)

    async with session.begin():
        await session.execute(
            RefreshToken.__table__.update()
            .where(RefreshToken.user_id == user.id, RefreshToken.status == TokenStatus.ACTIVE)
            .values(status=TokenStatus.REVOKED, revoked_at=datetime.now(timezone.utc))
        )

    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        device_info=payload.device_info or "web",
    )
    session.add(db_token)
    await session.commit()

    return RefreshResponse(
        access_token=access_token,
        refresh_token=refresh_value,
        expires_in=15 * 60,
    )


@router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(
    payload: LogoutRequest,
    session: AsyncSession = Depends(get_session),
):
    """Exchange a refresh token for a new access + refresh token pair.

    Implements rotation: the old refresh token is revoked and a new one
    issued.  Reuse of a revoked token triggers full session invalidation.
    """
    if not payload.refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token required")

    token_hash = TokenHasher.hash_token(payload.refresh_token)
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    result = await session.execute(stmt)
    db_token: Optional[RefreshToken] = result.scalar_one_or_none()

    if db_token is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if db_token.revoked_at is not None:
        # Token was already used → potential theft → revoke all for this user
        await session.execute(
            RefreshToken.__table__.update()
            .where(RefreshToken.user_id == db_token.user_id)
            .values(status=TokenStatus.REVOKED, revoked_at=datetime.now(timezone.utc))
        )
        await session.commit()
        raise HTTPException(status_code=401, detail="Token reuse detected; all sessions revoked")

    if ensure_aware(db_token.expires_at) < datetime.now(timezone.utc):
        db_token.status = TokenStatus.EXPIRED
        db_token.revoked_at = datetime.now(timezone.utc)
        await session.commit()
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # Validate the JWT payload inside the refresh token
    payload_claims = verify_token(payload.refresh_token, expected_type="refresh")
    if payload_claims is None or payload_claims.get("sub") != str(db_token.user_id):
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    # Rotation: revoke old, issue new
    new_access = create_access_token(str(db_token.user_id))
    new_refresh_value, new_expiry = create_refresh_token(str(db_token.user_id))
    new_hash = TokenHasher.hash_token(new_refresh_value)

    db_token.status = TokenStatus.REVOKED
    db_token.revoked_at = datetime.now(timezone.utc)
    db_token.replaced_by = None
    await session.flush()

    new_token = RefreshToken(
        user_id=db_token.user_id,
        token_hash=new_hash,
        expires_at=new_expiry,
        device_info=db_token.device_info,
    )
    session.add(new_token)
    await session.commit()

    return RefreshResponse(
        access_token=new_access,
        refresh_token=new_refresh_value,
        expires_in=15 * 60,
    )


@router.post("/logout")
async def logout(
    payload: LogoutRequest,
    session: AsyncSession = Depends(get_session),
):
    """Revoke a specific refresh token (or all if no token provided)."""
    if payload.refresh_token:
        token_hash = TokenHasher.hash_token(payload.refresh_token)
        stmt = (
            RefreshToken.__table__.update()
            .where(RefreshToken.token_hash == token_hash)
            .values(status=TokenStatus.REVOKED, revoked_at=datetime.now(timezone.utc))
        )
        await session.execute(stmt)
        await session.commit()
    return {"detail": "Logged out"}
