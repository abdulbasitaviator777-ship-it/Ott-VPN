from __future__ import annotations

import logging
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.database import get_session
from backend.api.models import User
from backend.auth.jwt import verify_token

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer(auto_error=False)


def _parse_bearer(credentials: Optional[HTTPAuthorizationCredentials]) -> Optional[str]:
    if credentials is None:
        return None
    if credentials.scheme.lower() != "bearer":
        return None
    return credentials.credentials


class RateLimiter:
    """Simple Redis-backed token-bucket rate limiter."""

    def __init__(self, redis_client=None, prefix: str = "rl"):
        self.redis = redis_client
        self.prefix = prefix

    async def check(self, key: str, limit: int, window_seconds: int) -> bool:
        if self.redis is None:
            return True
        bucket_key = f"{self.prefix}:{key}"
        now = int(__import__("time").time())
        pipe = self.redis.pipeline()
        pipe.zadd(bucket_key, {str(now): now})
        pipe.zremrangebyscore(bucket_key, 0, now - window_seconds)
        pipe.zcard(bucket_key)
        pipe.expire(bucket_key, window_seconds)
        results = await pipe.execute()
        count = results[2]
        return count <= limit


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_session),
) -> User:
    """FastAPI dependency: returns the authenticated User or raises 401."""
    token = _parse_bearer(credentials)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = verify_token(token, expected_type="access")
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    stmt = select(User).where(User.id == UUID(user_id))
    result = await session.execute(stmt)
    user: Optional[User] = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")

    return user


async def get_admin_user(
    user: User = Depends(get_current_user),
) -> User:
    """Dependency that requires the user to have an admin role."""
    if user.role.value != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return user
