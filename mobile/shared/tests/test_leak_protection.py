"""Tests for leak protection detection."""
import pytest
from unittest.mock import patch

from mobile.shared.leak_protection import LeakProtection, LeakCheckResult


class TestLeakProtection:
    def test_result_defaults(self):
        r = LeakCheckResult()
        assert r.dns_protected is True
        assert r.ipv6_protected is True
        assert r.detected_dns_servers == []

    def test_no_vpn_dns_no_leak_detection(self):
        lp = LeakProtection(vpn_public_ip="1.2.3.4", vpn_dns_servers=None)
        assert lp.vpn_dns_servers == []

    @pytest.mark.asyncio
    async def test_no_ipv6_means_protected(self):
        lp = LeakProtection(vpn_ipv6_prefix="fd86::/64")
        with patch.object(lp, "fetch_public_ip", return_value=None):
            leaked, _ = await lp.check_ipv6_leak()
            assert leaked is False

    @pytest.mark.asyncio
    async def test_ipv6_in_vpn_range_not_leaking(self):
        lp = LeakProtection(vpn_ipv6_prefix="fd86::/64")
        with patch.object(lp, "fetch_public_ip", return_value="fd86::5"):
            leaked, ipv6 = await lp.check_ipv6_leak()
            assert leaked is False
            assert ipv6 == "fd86::5"

    @pytest.mark.asyncio
    async def test_public_ipv6_outside_vpn_range_is_leak(self):
        lp = LeakProtection(vpn_ipv6_prefix="fd86::/64")
        with patch.object(lp, "fetch_public_ip", return_value="2001:db8::1"):
            leaked, ipv6 = await lp.check_ipv6_leak()
            assert leaked is True
            assert ipv6 == "2001:db8::1"

    @pytest.mark.asyncio
    async def test_dns_leak_when_system_dns_not_in_vpn_set(self):
        lp = LeakProtection(vpn_dns_servers=["10.66.0.1"])
        with patch.object(lp, "_get_system_dns", return_value=["8.8.8.8", "1.1.1.1"]):
            leaked, servers = await lp.check_dns_leak()
            assert leaked is True
            assert "8.8.8.8" in servers

    @pytest.mark.asyncio
    async def test_dns_no_leak_when_system_dns_matches_vpn(self):
        lp = LeakProtection(vpn_dns_servers=["10.66.0.1"])
        with patch.object(lp, "_get_system_dns", return_value=["10.66.0.1"]):
            leaked, servers = await lp.check_dns_leak()
            assert leaked is False

    @pytest.mark.asyncio
    async def test_full_check_all_protected(self):
        lp = LeakProtection(
            vpn_public_ip="103.109.56.1",
            vpn_dns_servers=["10.66.0.1"],
            vpn_ipv6_prefix="fd86::/64",
        )
        with patch.object(lp, "fetch_public_ip", side_effect=["103.109.56.1", None]):
            with patch.object(lp, "_get_system_dns", return_value=["10.66.0.1"]):
                result = await lp.run_full_check()
                assert result.dns_protected is True
                assert result.ipv6_protected is True
                assert result.public_ip_match is True
                assert result.public_ip == "103.109.56.1"

    @pytest.mark.asyncio
    async def test_full_check_detects_ipMismatch(self):
        lp = LeakProtection(
            vpn_public_ip="103.109.56.1",
            vpn_dns_servers=["10.66.0.1"],
            vpn_ipv6_prefix="fd86::/64",
        )
        with patch.object(lp, "fetch_public_ip", side_effect=["203.0.113.5", None]):
            with patch.object(lp, "_get_system_dns", return_value=["10.66.0.1"]):
                result = await lp.run_full_check()
                assert result.public_ip_match is False
                assert result.public_ip == "203.0.113.5"