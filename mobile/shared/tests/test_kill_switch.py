"""Tests for the kill switch."""
import platform
import pytest
from unittest.mock import patch, MagicMock

from mobile.shared.kill_switch import KillSwitch, KillSwitchState, KillSwitchRules


class TestKillSwitch:
    def test_initial_state_disabled(self):
        ks = KillSwitch(tunnel_interface="wg0", tunnel_ip="10.66.0.5")
        assert ks.state == KillSwitchState.DISABLED

    def test_rules_dataclass(self):
        rules = KillSwitchRules(chain_name="TEST")
        assert rules.chain_name == "TEST"
        assert rules.rules == []

    def test_status_report(self):
        ks = KillSwitch(tunnel_interface="wg0", tunnel_ip="10.66.0.5", dns_servers=["10.66.0.1"])
        status = ks.get_status()
        assert status["state"] == "disabled"
        assert status["tunnel_interface"] == "wg0"
        assert status["tunnel_ip"] == "10.66.0.5"
        assert "10.66.0.1" in status["dns_servers"]

    @pytest.mark.asyncio
    async def test_enable_unsupported_platform(self):
        """On unsupported platforms (e.g. Windows), kill switch returns ERROR."""
        ks = KillSwitch(tunnel_interface="wg0")
        with patch.object(platform, "system", return_value="Windows"):
            state = await ks.enable()
            assert state == KillSwitchState.ERROR

    @pytest.mark.asyncio
    async def test_enable_linux_without_iptables(self):
        """On Linux without iptables, kill switch returns ERROR."""
        ks = KillSwitch(tunnel_interface="wg0")
        with patch.object(platform, "system", return_value="Linux"):
            with patch.object(ks, "_iptables", None):
                with patch.object(ks, "_nft", None):
                    state = await ks.enable()
                    assert state == KillSwitchState.ERROR