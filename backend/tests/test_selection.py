"""Unit tests for server selection scoring."""
import pytest

from backend.api.models import Server, ServerStatus, ServerHealth
from backend.servers.selection import ServerSelector, server_health_value


def _make_server(
    sid: str = "in-mum-01",
    status: ServerStatus = ServerStatus.HEALTHY,
    current_peers: int = 10,
    capacity: int = 100,
    latency: float = 50.0,
    loss: float = 0.0,
    load: float = 20.0,
    city: str = "Mumbai",
):
    s = Server(
        id=sid,
        hostname=f"{sid}.vpn.example",
        country="IN",
        city=city,
        region="Maharashtra",
        ipv4="103.1.1.1",
        wireguard_pubkey="dummypubkey==",
        wireguard_port=51820,
        capacity=capacity,
        current_peers=current_peers,
        status=status,
    )
    s.health_records = [
        ServerHealth(
            server_id=sid,
            latency_ms=latency,
            packet_loss=loss,
            load_percent=load,
            geolocated_in=True,
        )
    ]
    return s


class TestServerSelector:
    def test_compute_score_lower_is_better(self):
        low = _make_server(latency=30, load=10)
        high = _make_server(latency=100, load=70)
        s_low = ServerSelector.compute_score(low)
        s_high = ServerSelector.compute_score(high)
        assert s_low < s_high

    def test_degraded_server_penalized(self):
        healthy = _make_server(status=ServerStatus.HEALTHY, latency=30)
        degraded = _make_server(status=ServerStatus.DEGRADED, latency=30)
        assert ServerSelector.compute_score(degraded) > ServerSelector.compute_score(healthy)

    def test_overloaded_server_penalized(self):
        normal = _make_server(current_peers=50, capacity=100)
        overloaded = _make_server(current_peers=95, capacity=100)
        assert ServerSelector.compute_score(overloaded) > ServerSelector.compute_score(normal)

    def test_mumbai_example_scoring(self):
        mumbai = _make_server(sid="in-mum-01", city="Mumbai", latency=38, load=21)
        delhi = _make_server(sid="in-del-01", city="Delhi", latency=42, load=17)
        hyd = _make_server(sid="in-hyd-01", city="Hyderabad", latency=51, load=34)
        blr = _make_server(sid="in-blr-01", city="Bangalore", latency=58, load=12)

        scores = {s.city: ServerSelector.compute_score(s) for s in [mumbai, delhi, hyd, blr]}
        best_city = min(scores, key=scores.get)
        assert best_city == "Mumbai"

    def test_server_health_value_extraction(self):
        server = _make_server(latency=45.2)
        assert server_health_value(server, "latency_ms") == 45.2
        empty_server = Server(id="test", hostname="h", country="IN", city="x")
        assert server_health_value(empty_server, "latency_ms", default=999.0) == 999.0
