import os
import sys

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Root conftest.py handles DB engine initialisation, table creation/drop,
# and the shared `client` fixture.  This conftest only provides the
# db_session fixture for direct DB access in tests.


@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    from backend.api.database import _session_factory

    assert _session_factory is not None
    async with _session_factory() as session:
        yield session
        await session.rollback()
