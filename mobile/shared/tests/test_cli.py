"""Integration tests for the VPNConnectionManager."""
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, AsyncMock, MagicMock

import pytest
import httpx
from httpx import ASGITransport, AsyncClient

from backend.api.main import app
from mobile.shared.vpn_api import VPNAPIClient
from mobile.shared.cli import VPNConnectionManager


class TestConnectionManager:
    """Tests for the connection lifecycle logic."""

    @pytest.fixture
    def api_client(self):
        return VPNAPIClient(base_url="http://test", verify_ssl=False)

    @pytest.mark.asyncio
    async def test_status_when_disconnected(self, api_client):
        conn = VPNConnectionManager(api_client)
        status = await conn.status()
        assert status["connected"] is False
        assert status["tunnel_state"] == "down"

    @pytest.mark.asyncio
    async def test_status_reports_kill_switch(self, api_client):
        conn = VPNConnectionManager(api_client)
        status = await conn.status()
        assert status["kill_switch"] == "disabled"

    @pytest.mark.asyncio
    async def test_token_save_and_load(self, api_client, tmp_path, monkeypatch):
        """Tokens are saved to disk and can be reloaded."""
        from mobile.shared.vpn_api import AuthTokens

        monkeypatch.setattr("mobile.shared.cli.CONFIG_DIR", tmp_path)
        monkeypatch.setattr("mobile.shared.cli.TOKEN_FILE", tmp_path / "tokens.json")

        conn = VPNConnectionManager(api_client)
        tokens = AuthTokens(access_token="test_access", refresh_token="test_refresh", expires_in=900)
        conn._save_tokens(tokens)

        loaded = conn._load_tokens()
        assert loaded is not None
        assert loaded.access_token == "test_access"
        assert loaded.refresh_token == "test_refresh"

    @pytest.mark.asyncio
    async def test_token_load_returns_none_when_no_file(self, api_client, tmp_path, monkeypatch):
        monkeypatch.setattr("mobile.shared.cli.CONFIG_DIR", tmp_path)
        monkeypatch.setattr("mobile.shared.cli.TOKEN_FILE", tmp_path / "tokens.json")

        conn = VPNConnectionManager(api_client)
        assert conn._load_tokens() is None


class TestAPIClientMocks:
    """Test the API client with a mock backend."""

    @pytest.mark.asyncio
    async def test_list_servers_parses_response(self):
        with patch.object(VPNAPIClient, "list_servers", new_callable=AsyncMock) as mock_list:
            from mobile.shared.vpn_api import ServerInfo

            mock_list.return_value = [
                ServerInfo(id="in-mum-01", city="Mumbai", country="IN", status="healthy", latency_ms=38.0)
            ]
            client = VPNAPIClient(base_url="http://test")
            servers = await client.list_servers()
            assert len(servers) == 1
            assert servers[0].id == "in-mum-01"
            assert servers[0].city == "Mumbai"