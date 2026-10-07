import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash

from backend.api.config import settings

logger = logging.getLogger(__name__)

_ph = PasswordHasher(
    time_cost=settings.argon2_time_cost,
    memory_cost=settings.argon2_memory_cost,
    parallelism=settings.argon2_parallelism,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return _ph.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False
    except InvalidHash:
        return False


def needs_rehash(password_hash: str) -> bool:
    """Check if the hash uses outdated parameters and should be re-hashed."""
    return _ph.check_needs_rehash(password_hash)


class TokenHasher:
    """Hash tokens for storage using SHA-256."""

    @staticmethod
    def hash_token(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()


class RefreshTokenManager:
    """Manages refresh-token issuance, verification, and rotation."""

    @staticmethod
    def create_token_value() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def compute_expiry() -> datetime:
        return datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)

    @staticmethod
    def compute_refresh_id() -> str:
        return str(secrets.token_urlsafe(32))
