"""Integration tests for server and VPN config endpoints."""
import uuid as _uuid

import pytest
from httpx import AsyncClient

from backend.api.models import Server, ServerStatus, Plan


@pytest.fixture(autouse=True)
async def _seed_servers():
    from backend.api.database import _session_factory, create_all_tables
    await create_all_tables()
    async with _session_factory() as session:
        # Seed an Indian server in Mumbai
        server = Server(
            id="in-mum-01",
            hostname="mumbai-01.ottvpn.in",
            country="IN",
            city="Mumbai",
            region="Maharashtra",
            latitude=19.0760,
            longitude=72.8777,
            ipv4="103.109.56.1",
            wireguard_pubkey="dGVzdFB1YmxjQ2VydEFjY291bnRLZXk=",
            wireguard_port=51820,
            wireguard_net="10.66.0.0/24",
            wireguard_net6="fd86::/64",
            wireguard_preshared=True,
            protocol="wireguard",
            status=ServerStatus.HEALTHY,
            capacity=100,
            current_peers=5,
            ott_zee5="pass",
            ott_jiohotstar="pass",
        )
        from backend.api.models import ServerHealth
        server.health_records = [
            ServerHealth(
                server_id="in-mum-01",
                latency_ms=38.5,
                packet_loss=0.0,
                load_percent=21.0,
                geolocated_in=True,
                detected_country="IN",
            )
        ]
        session.add(server)
        await session.commit()
        yield
        # teardown
        from sqlalchemy import delete
        await session.execute(delete(Server))
        await session.commit()


class TestServerEndpoints:
    @pytest.fixture(autouse=True)
    async def _setup(self, client: AsyncClient):
        self.client = client

    async def test_list_indian_servers(self):
        resp = await self.client.get("/api/servers/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["country"] == "IN"
        assert len(data["servers"]) >= 1
        assert data["servers"][0]["id"] == "in-mum-01"
        assert data["servers"][0]["city"] == "Mumbai"
        assert data["servers"][0]["status"] == "healthy"

    async def test_list_by_city(self):
        resp = await self.client.get("/api/servers/?city=Mumbai")
        assert resp.status_code == 200
        assert resp.json()["servers"][0]["city"] == "Mumbai"

    async def test_get_server_detail(self):
        resp = await self.client.get("/api/servers/in-mum-01")
        assert resp.status_code == 200
        data = resp.json()
        assert data["hostname"] == "mumbai-01.ottvpn.in"
        assert data["wireguard_pubkey"] == "dGVzdFB1YmxjQ2VydEFjY291bnRLZXk="
        assert data["ipv4"] == "103.109.56.1"

    async def test_get_nonexistent_server(self):
        resp = await self.client.get("/api/servers/does-not-exist")
        assert resp.status_code == 404

    async def test_recommended_servers(self):
        resp = await self.client.get("/api/servers/recommended")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    async def test_server_response_no_private_key(self):
        """Server detail must never expose private keys."""
        resp = await self.client.get("/api/servers/in-mum-01")
        assert resp.status_code == 200
        body = resp.text
        assert "PrivateKey" not in body
        assert "wireguard_privkey" not in body.lower()


class TestVpnConfigEndpoint:
    @pytest.fixture(autouse=True)
    async def _auth(self, client: AsyncClient):
        self.client = client
        email = f"vpn_{_uuid.uuid4().hex[:8]}@example.com"
        await client.post("/api/auth/register", json={"email": email, "password": "Str0ngP@ss1"})
        login = await client.post("/api/auth/login", json={"email": email, "password": "Str0ngP@ss1"})
        token = login.json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"
        yield

    async def test_generate_config_auto(self):
        resp = await self.client.post("/api/vpn/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["server_id"] == "in-mum-01"
        assert "[Interface]" in data["config"]
        assert "[Peer]" in data["config"]
        assert "PrivateKey" in data["config"]
        assert "PublicKey = dGVzdFB1YmxjQ2VydEFjY291bnRLZXk=" in data["config"]
        assert "10.66.0" in data["config"]

    async def test_generate_config_specific_server(self):
        resp = await self.client.post("/api/vpn/config", params={"server_id": "in-mum-01"})
        assert resp.status_code == 200

    async def test_generate_config_no_private_key_in_response(self):
        resp = await self.client.post("/api/vpn/config")
        assert resp.status_code == 200
        assert "server_privkey" not in resp.text.lower()

    async def test_generate_config_requires_auth(self):
        self.client.headers.pop("Authorization", None)
        resp = await self.client.post("/api/vpn/config")
        assert resp.status_code == 401

    async def test_revoke_config(self):
        # Generate a config first
        resp = await self.client.post("/api/vpn/config")
        conf = resp.json()
        peer_id = resp.json().get("peer_id")
        if peer_id:
            rev = await self.client.post("/api/vpn/revoke", params={"peer_id": peer_id})
            assert rev.status_code == 200

    async def test_vpn_status(self):
        resp = await self.client.post("/api/vpn/config")
        status = await self.client.get("/api/vpn/status")
        assert status.status_code == 200
        data = status.json()
        assert data["connected"] is True
