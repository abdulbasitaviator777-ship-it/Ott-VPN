"""Unit tests for WireGuard key generation and config creation."""
import base64

import pytest

from backend.vpn.wireguard import (
    generate_keypair,
    generate_preshared_key,
    allocate_tunnel_ip,
    allocate_tunnel_ip6,
    build_wireguard_config,
    build_server_config,
    parse_wg_config_key,
)


class TestKeyGeneration:
    def test_keypair_is_valid_base64(self):
        priv, pub = generate_keypair()
        assert len(priv) > 0
        assert len(pub) > 0
        # WireGuard keys are base64-encoded 32-byte values
        priv_bytes = base64.b64decode(priv)
        pub_bytes = base64.b64decode(pub)
        assert len(priv_bytes) == 32
        assert len(pub_bytes) == 32

    def test_keypair_is_unique(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        assert priv1 != priv2
        assert pub1 != pub2

    def test_preshared_key_is_valid_base64(self):
        psk = generate_preshared_key()
        psk_bytes = base64.b64decode(psk)
        assert len(psk_bytes) == 32


class TestTunnelIpAllocation:
    def test_allocate_v4(self):
        used = {"10.66.0.1", "10.66.0.2"}
        ip = allocate_tunnel_ip("10.66.0.0/24", used)
        assert ip == "10.66.0.3"

    def test_allocate_v6(self):
        used = {"fd86::1"}
        ip = allocate_tunnel_ip6("fd86::/64", used)
        assert ip == "fd86::2"

    def test_allocate_pools_exhausted(self):
        # 10.66.0.0/24 has hosts 1..254 (254 addresses)
        used = {f"10.66.0.{i}" for i in range(1, 255)}
        with pytest.raises(RuntimeError, match="No free IPs"):
            allocate_tunnel_ip("10.66.0.0/24", used)


class TestConfigGeneration:
    def test_client_config_has_required_sections(self):
        config = build_wireguard_config(
            client_private_key="privkeybase64==",
            server_public_key="serverpubkeybase64==",
            server_endpoint="mumbai.vpn.example",
            server_port=51820,
            tunnel_ip="10.66.0.5/24",
            tunnel_ip6="fd86::5/64",
            preshared_key="pskbase64==",
            dns_servers=["10.66.0.1"],
        )
        assert "[Interface]" in config
        assert "[Peer]" in config
        assert "PrivateKey = privkeybase64==" in config
        assert "PublicKey = serverpubkeybase64==" in config
        assert "Endpoint = mumbai.vpn.example:51820" in config
        assert "Address = 10.66.0.5/24, fd86::5/64" in config
        assert "DNS = 10.66.0.1" in config
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in config
        assert "PersistentKeepalive = 25" in config
        assert "PresharedKey = pskbase64==" in config
        assert "MTU = 1280" in config

    def test_config_no_preshared(self):
        config = build_wireguard_config(
            client_private_key="k",
            server_public_key="pk",
            server_endpoint="ep",
            server_port=51820,
            tunnel_ip="10.66.0.5/24",
            tunnel_ip6=None,
            preshared_key=None,
            dns_servers=["8.8.8.8"],
        )
        assert "PresharedKey" not in config
        assert "fd86::5" not in config

    def test_server_config_has_privatekey_only_server_side(self):
        config = build_server_config(
            server_private_key="serverprivkey==",
            tunnel_net="10.66.0.0/24",
            tunnel_net6="fd86::/64",
            listen_port=51820,
            dns_forward="10.66.0.1",
        )
        assert "[Interface]" in config
        assert "PrivateKey = serverprivkey==" in config
        assert "ListenPort = 51820" in config
        assert "Address = 10.66.0.0/24, fd86::/64" in config
        assert "PostUp" in config
        assert "PostDown" in config

    def test_parse_config_key(self):
        config = "[Interface]\nAddress = 10.0.0.2/24\n"
        assert parse_wg_config_key(config, "Address") == "10.0.0.2/24"
        assert parse_wg_config_key(config, "PrivateKey") is None
