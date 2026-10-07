"""Root-level pytest configuration shared by all test directories."""
import os
import sys

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import backend.api.database as db_module
from backend.api.database import Base
from backend.api.main import app


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
async def _ensure_tables():
    """Create all tables before each test, drop after for isolation."""
    if db_module._engine is None:
        db_path = os.environ.get("TEST_DB_PATH", "./test_ottvpn.db")
        db_module.init_db(f"sqlite+aiosqlite:///{db_path}")
    assert db_module._engine is not None
    async with db_module._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with db_module._engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session():
    assert db_module._session_factory is not None
    async with db_module._session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
