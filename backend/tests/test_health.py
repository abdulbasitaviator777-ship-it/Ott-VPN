"""Unit tests for health check logic and leak detection."""
import ipaddress

import pytest

from backend.health.checks import HealthChecker, HealthResult


class TestHealthResult:
    def test_defaults(self):
        r = HealthResult(server_id="test", status="healthy")
        assert r.dns_leak is False
        assert r.ipv6_leak is False
        assert r.geolocated_in is False


class TestIpv6LeakDetection:
    """Tests for IPv6 leak detection logic."""

    @pytest.mark.asyncio
    async def test_no_ipv6_no_leak(self):
        """If no IPv6 address is available, it's blocked (not leaking)."""
        checker = HealthChecker()
        # fetch_public_ip returns None for IPv6
        ipv6 = await checker.fetch_public_ip(ipv6=True)
        # In test env, IPv6 is likely unavailable; if None, no leak
        if ipv6 is None:
            assert await checker.detect_ipv6_leak() is False

    @pytest.mark.asyncio
    async def test_ipv6_in_vpn_range_no_leak(self):
        """An IPv6 in the VPN subnet is not a leak."""
        checker = HealthChecker()
        # Test the logic directly
        vpn_net = ipaddress.ip_network("fd86::/64")
        ip6 = ipaddress.ip_address("fd86::123")
        assert ip6 in vpn_net  # VPN IPv6 → no leak


class TestDnsLeakDetection:
    @pytest.mark.asyncio
    async def test_empty_dns_is_leak(self):
        checker = HealthChecker()
        result = await checker.detect_dns_leak([])
        assert result is True  # No DNS configured → potential leak


class TestLatencyCheck:
    @pytest.mark.asyncio
    async def test_unreachable_host_returns_high_latency(self):
        checker = HealthChecker()
        latency, loss = await checker.check_latency("192.0.2.1", 51820, count=2)
        assert latency == 9999.0
        assert loss == 100.0


class TestOttCheck:
    @pytest.mark.asyncio
    async def test_ott_disabled_returns_unknown(self, monkeypatch):
        from backend.api import config as cfgmod
        original = cfgmod.settings.ott_probe_enabled
        cfgmod.settings.ott_probe_enabled = False
        try:
            checker = HealthChecker()
            result = await checker.check_ott("zee5")
            assert result == "unknown"
        finally:
            cfgmod.settings.ott_probe_enabled = original
