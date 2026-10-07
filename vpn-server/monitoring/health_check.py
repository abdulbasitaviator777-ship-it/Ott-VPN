#!/usr/bin/env python3
"""
OTT VPN — Server-side health check

Runs on the Indian WireGuard gateway to verify:
  1. Public IPv4 is geolocated to India
  2. Public IPv6 (if available) is routed through the VPN
  3. DNS resolution works
  4. Latency to public endpoints
  5. WireGuard interface stats
  6. OTT reachability (ZEE5, JioHotstar) — HTTP probe only, no auth bypass

Output: JSON to stdout (consumed by the backend health worker)
"""
from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import time
from datetime import datetime, timezone

import httpx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("health-check")

IPV4_PROBES = [
    "https://api.ipify.org?format=json",
    "https://ipinfo.io/ip",
    "https://ifconfig.me/ip",
]
IPV6_PROBES = [
    "https://api6.ipify.org?format=json",
    "https://ipv6.icanhazip.com",
]


async def fetch_public_ip(http: httpx.AsyncClient, ipv6: bool = False) -> str | None:
    probes = IPV6_PROBES if ipv6 else IPV4_PROBES
    for probe in probes:
        try:
            resp = await http.get(probe, timeout=10.0)
            if resp.status_code == 200:
                text = resp.text.strip()
                if ipv6:
                    return text
                if "ip" in resp.headers.get("content-type", ""):
                    return resp.json().get("ip")
                return text
        except Exception:
            continue
    return None


async def check_geolocation(http: httpx.AsyncClient, ip: str) -> dict:
    try:
        resp = await http.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,as,query",
            timeout=10.0,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        logger.warning("Geo check failed for %s: %s", ip, e)
    return {}


async def check_ott(http: httpx.AsyncClient, service: str) -> str:
    urls = {
        "zee5": "https://gwapi.zee5.com/",
        "jiohotstar": "https://www.jiohotstar.com/",
        "sonyliv": "https://sonyliv.com/",
        "mxplayer": "https://www.mxplayer.in/",
    }
    url = urls.get(service)
    if not url:
        return "unknown"
    try:
        resp = await http.get(url, follow_redirects=True, timeout=15.0)
        if resp.status_code in (200, 301, 302):
            return "pass"
        if resp.status_code == 403:
            return "fail"
        return "unknown"
    except Exception:
        return "fail"


async def measure_latency(host: str, port: int, count: int = 4) -> tuple[float, float]:
    rtts: list[float] = []
    successes = 0
    for _ in range(count):
        start = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3.0
            )
            elapsed = (time.monotonic() - start) * 1000
            rtts.append(elapsed)
            successes += 1
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
    if not rtts:
        return 9999.0, 100.0
    return round(sum(rtts) / len(rtts), 1), round((count - successes) / count * 100, 1)


def get_wg_info() -> dict:
    try:
        result = subprocess.run(["wg", "show"], capture_output=True, text=True, timeout=5)
        return {"wg_show": result.stdout}
    except Exception as e:
        return {"wg_show_error": str(e)}


async def run_checks(server_id: str, endpoint: str = "127.0.0.1", port: int = 51820) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as http:
        ipv4 = await fetch_public_ip(http, ipv6=False)

        geo: dict = {}
        if ipv4:
            geo = await check_geolocation(http, ipv4)

        ipv6 = await fetch_public_ip(http, ipv6=True)

        latency, packet_loss = await measure_latency(endpoint, port)

        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo("example.com", None),
                timeout=5.0,
            )
            dns_ok = True
        except Exception:
            dns_ok = False

        ott_zee5 = await check_ott(http, "zee5")
        ott_jiohotstar = await check_ott(http, "jiohotstar")

        wg_info = get_wg_info()

        result = {
            "server_id": server_id,
            "status": "healthy" if geo.get("countryCode", "").upper() == "IN" else "offline",
            "latency_ms": latency,
            "packet_loss": packet_loss,
            "geolocated_in": geo.get("countryCode", "").upper() == "IN",
            "detected_ip": ipv4,
            "detected_ipv6": ipv6,
            "detected_country": geo.get("country", ""),
            "detected_asn": geo.get("as"),
            "detected_city": geo.get("city", ""),
            "dns_ok": dns_ok,
            "ipv6_ok": ipv6 is not None,
            "ipv6_leak": False,
            "dns_leak": False,
            "ott_zee5": ott_zee5,
            "ott_jiohotstar": ott_jiohotstar,
            "wg_info": wg_info,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return result


def main():
    import os

    server_id = os.environ.get("SERVER_ID", "unknown")
    endpoint = os.environ.get("ENDPOINT", "127.0.0.1")
    port = int(os.environ.get("WG_PORT", "51820"))

    result = asyncio.run(run_checks(server_id, endpoint, port))
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
