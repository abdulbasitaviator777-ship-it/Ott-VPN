"""Unit tests for authentication: registration, login, token rotation."""
import asyncio
from backend.api.database import init_db, _session_factory
from backend.api.models import TokenStatus, User, RefreshToken
from sqlalchemy import select
import uuid as _uuid
