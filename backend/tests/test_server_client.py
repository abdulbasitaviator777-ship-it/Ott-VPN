"""Tests for the WireGuard server provisioning client."""
import hashlib
from unittest.mock import patch

import httpx
import pytest

from backend.vpn.server import WireGuardServerClient


class TestWireGuardServerClient:
    """Unit tests for the peer-manager HTTP client (no real network)."""

    @pytest.fixture
    def client(self):
        return WireGuardServerClient(host="127.0.0.1", port=9123, secret="testsecret123")

    def test_auth_token_is_sha256(self, client):
        expected = hashlib.sha256("testsecret123".encode()).hexdigest()
        assert client.auth_token == expected

    def test_auth_token_is_deterministic(self, client):
        assert client.auth_token == client.auth_token

    def test_headers_contain_auth(self, client):
        headers = client._headers()
        assert "X-Auth-Token" in headers
        assert headers["Content-Type"] == "application/json"

    @pytest.mark.asyncio
    async def test_add_peer_success(self, client):
        mock_response = httpx.Response(201, json={"status": "peer added"})
        with patch.object(client.http, "post", return_value=mock_response) as mock_post:
            result = await client.add_peer(
                public_key="dGVzdFB1Ymxj",
                preshared_key="dGVzdFBzaA==",
                allowed_ips="0.0.0.0/0, ::/0",
                tunnel_ip="10.66.0.5/24",
                tunnel_ip6="fd86::5/64",
            )
            assert result is True
            assert mock_post.call_count == 1

    @pytest.mark.asyncio
    async def test_add_peer_failure(self, client):
        mock_response = httpx.Response(400, json={"error": "bad request"})
        with patch.object(client.http, "post", return_value=mock_response):
            result = await client.add_peer(
                public_key="dGVzdFB1Ymxj",
                preshared_key=None,
                allowed_ips="0.0.0.0/0",
                tunnel_ip="10.66.0.5/24",
            )
            assert result is False

    @pytest.mark.asyncio
    async def test_add_peer_network_error(self, client):
        with patch.object(client.http, "post", side_effect=httpx.ConnectError("refused")):
            result = await client.add_peer(
                public_key="dGVzdFB1Ymxj",
                preshared_key=None,
                allowed_ips="0.0.0.0/0",
                tunnel_ip="10.66.0.5/24",
            )
            assert result is False

    @pytest.mark.asyncio
    async def test_remove_peer_success(self, client):
        with patch.object(client.http, "delete", return_value=httpx.Response(200, json={"status": "peer removed"})):
            result = await client.remove_peer("dGVzdFB1Ymxj")
            assert result is True

    @pytest.mark.asyncio
    async def test_get_server_info(self, client):
        mock_data = {
            "interface": "wg0",
            "public_key": "dGVzdFB1Ymxj",
            "tunnel_net_v4": "10.66.0.0/24",
            "tunnel_net_v6": "fd86::/64",
        }
        with patch.object(client.http, "get", return_value=httpx.Response(200, json=mock_data)):
            info = await client.get_server_info()
            assert info["interface"] == "wg0"
            assert info["public_key"] == "dGVzdFB1Ymxj"

    def test_base_url_format(self, client):
        assert client.base_url == "http://127.0.0.1:9123"