import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError, InvalidIssuerError

from backend.api.config import settings

logger = logging.getLogger(__name__)

_ISSUER = "ott-vpn-backend"
_AUDIENCE = "ott-vpn-client"


def now_utc() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def ensure_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Convert a naive datetime to UTC-aware.  None passes through."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def create_access_token(
    subject: str,
    extra_claims: Optional[dict[str, Any]] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a short-lived JWT access token."""
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(minutes=settings.access_token_expire_minutes)
    to_encode: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": str(subject),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": _generate_jti(),
    }
    if extra_claims:
        to_encode.update(extra_claims)
    encoded = jwt.encode(to_encode, settings.secret_key, algorithm=settings.jwt_algorithm)
    return encoded


def create_refresh_token(subject: str, expires_delta: Optional[timedelta] = None) -> tuple[str, datetime]:
    """Create a long-lived JWT-style refresh token (opaque string).

    Returns the token string and its absolute expiry datetime.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is None:
        expires_delta = timedelta(days=settings.refresh_token_expire_days)
    exp = now + expires_delta
    payload: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": str(subject),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": _generate_jti(),
    }
    token_str = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return token_str, exp


def verify_token(token: str, expected_type: str = "access") -> Optional[dict[str, Any]]:
    """Verify a JWT and return its payload.  Returns None on failure."""
    try:
        payload = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
            issuer=_ISSUER,
            audience=_AUDIENCE,
            options={"require": ["exp", "sub", "type"]},
        )
    except ExpiredSignatureError:
        logger.info("Token expired")
        return None
    except InvalidIssuerError:
        logger.warning("Invalid issuer in token")
        return None
    except InvalidTokenError as exc:
        logger.warning("Invalid token: %s", exc)
        return None

    if payload.get("type") != expected_type:
        logger.warning("Token type mismatch: expected %s, got %s", expected_type, payload.get("type"))
        return None
    return payload


def _generate_jti() -> str:
    import secrets

    return secrets.token_urlsafe(16)
