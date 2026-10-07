"""Integration tests for authentication endpoints."""
import uuid as _uuid

import pytest
from httpx import AsyncClient


class TestAuth:
    """Tests for /api/auth/{register,login,refresh,logout}."""

    @pytest.fixture(autouse=True)
    async def _setup(self, client: AsyncClient):
        self.client = client
        # Ensure a clean DB with tables created
        from backend.api.database import init_db, _session_factory, create_all_tables
        if _session_factory is None:
            init_db()
        await create_all_tables()

    async def test_register_success(self):
        email = f"register_{_uuid.uuid4().hex[:8]}@example.com"
        resp = await self.client.post(
            "/api/auth/register",
            json={"email": email, "password": "Str0ngP@ss1"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["token_type"] == "bearer"
        assert "access_token" in data
        assert data["expires_in"] == 900

    async def test_register_weak_password(self):
        email = f"weak_{_uuid.uuid4().hex[:8]}@example.com"
        resp = await self.client.post(
            "/api/auth/register",
            json={"email": email, "password": "weak"},
        )
        assert resp.status_code == 422

    async def test_register_duplicate_email(self):
        email = f"dup_{_uuid.uuid4().hex[:8]}@example.com"
        r1 = await self.client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        assert r1.status_code == 201
        r2 = await self.client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        assert r2.status_code == 409

    async def test_login_success(self):
        email = f"login_{_uuid.uuid4().hex[:8]}@example.com"
        await self.client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        resp = await self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "Str0ngP@ss1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data

    async def test_login_wrong_password(self):
        email = f"wrong_{_uuid.uuid4().hex[:8]}@example.com"
        await self.client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        resp = await self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "WrongP@ss1"},
        )
        assert resp.status_code == 401

    async def test_token_rotation(self):
        """Refresh produces a new refresh token and invalidates the old."""
        email = f"rot_{_uuid.uuid4().hex[:8]}@example.com"
        await self.client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        login = await self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "Str0ngP@ss1"},
        )
        old_refresh = login.json()["refresh_token"]

        # Use the refresh token
        resp = await self.client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
        assert resp.status_code == 200
        new_refresh = resp.json()["refresh_token"]
        assert new_refresh != old_refresh

        # Reusing the old token should be detected as theft
        resp2 = await self.client.post("/api/auth/refresh", json={"refresh_token": old_refresh})
        assert resp2.status_code == 401

    async def test_unauthorized_access_without_token(self):
        resp = await self.client.get("/api/vpn/status")
        assert resp.status_code == 401

    async def test_logout(self):
        email = f"logout_{_uuid.uuid4().hex[:8]}@example.com"
        login = await self.client.post(
            "/api/auth/login",
            json={"email": email, "password": "Str0ngP@ss1"},
        )
        # Register first
        await self.client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        login = await self.client.post("/api/auth/login", json={"email": email, "password": "Str0ngP@ss1"})
        refresh = login.json()["refresh_token"]
        resp = await self.client.post("/api/auth/logout", json={"refresh_token": refresh})
        assert resp.status_code == 200
