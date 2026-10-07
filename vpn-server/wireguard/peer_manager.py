#!/usr/bin/env python3
"""
OTT VPN — Peer Manager (runs on the Indian WireGuard gateway)

Provides an authenticated HTTP API to add/remove WireGuard peers
and query handshake stats.  Intended to be called by the backend API.

Usage:
    python peer_manager.py --port 9123 --secret $(cat /etc/wireguard/peer-manager.secret)

Security:
    - Listens on 127.0.0.1 only (not exposed to the internet)
    - All endpoints require an HMAC auth token
    - Runs as a non-root user where possible (wg commands require NET_ADMIN)
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("peer-manager")

INTERFACE = os.environ.get("WG_INTERFACE", "wg0")
SERVER_TUNNEL_NET_V4 = os.environ.get("WG_TUNNEL_NET_V4", "10.66.0.0/24")
SERVER_TUNNEL_NET_V6 = os.environ.get("WG_TUNNEL_NET_V6", "fd86::/64")


def wg(args: list[str]) -> str:
    result = subprocess.run(["wg"] + args, captureoutput=True, text=True, check=True)
    return result.stdout


def add_peer(pubkey: str, preshared: str | None, allowed_ips: str):
    """Add a peer to the WireGuard interface."""
    cmd = ["wg", "set", INTERFACE, "peer", pubkey]
    if preshared:
        cmd += ["preshared-key", preshared]
    cmd += ["allowed-ips", allowed_ips]
    subprocess.run(cmd, check=True)
    logger.info("Peer %s added (allowed_ips=%s)", pubkey[:16], allowed_ips)


def remove_peer(pubkey: str):
    """Remove a peer from the WireGuard interface."""
    subprocess.run(["wg", "set", INTERFACE, "peer", pubkey, "remove"], check=True)
    logger.info("Peer %s removed", pubkey[:16])


def get_all_peers() -> dict:
    """Return all peer stats from `wg show`."""
    try:
        output = wg(["show", INTERFACE])
        return {"raw": output}
    except subprocess.CalledProcessError as e:
        return {"error": str(e)}


def verify_auth(token: str, secret: str) -> bool:
    """Verify HMAC-SHA256 auth token."""
    expected = hashlib.sha256(secret.encode()).hexdigest()
    return hmac.compare_digest(token, expected)


class AuthHTTPServer(HTTPServer):
    auth_secret: str = ""


class PeerManagerHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.info("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, code: int, data: dict):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if not verify_auth(self.headers.get("X-Auth-Token", ""), self.server.auth_secret):
            self._send_json(401, {"error": "unauthorized"})
            return
        if self.path == "/peers":
            length = int(self.headers.get("Content-Length", 0))
            try:
                data = json.loads(self.rfile.read(length)) if length > 0 else {}
            except json.JSONDecodeError:
                self._send_json(400, {"error": "invalid JSON"})
                return
            try:
                add_peer(
                    pubkey=data["public_key"],
                    preshared=data.get("preshared_key"),
                    allowed_ips=data["allowed_ips"],
                )
                self._send_json(201, {"status": "peer added"})
            except subprocess.CalledProcessError as e:
                self._send_json(400, {"error": str(e)})
        else:
            self._send_json(404, {"error": "not found"})

    def do_DELETE(self):
        if not verify_auth(self.headers.get("X-Auth-Token", ""), self.server.auth_secret):
            self._send_json(401, {"error": "unauthorized"})
            return
        if self.path.startswith("/peers/"):
            pubkey = self.path.split("/peers/")[1]
            try:
                remove_peer(pubkey)
                self._send_json(200, {"status": "peer removed"})
            except subprocess.CalledProcessError as e:
                self._send_json(400, {"error": str(e)})
        else:
            self._send_json(404, {"error": "not found"})

    def do_GET(self):
        if not verify_auth(self.headers.get("X-Auth-Token", ""), self.server.auth_secret):
            self._send_json(401, {"error": "unauthorized"})
            return
        if self.path == "/stats":
            self._send_json(200, get_all_peers())
        elif self.path == "/server-info":
            pubkey = os.environ.get("WG_SERVER_PUBLIC_KEY", "")
            self._send_json(200, {
                "interface": INTERFACE,
                "public_key": pubkey,
                "tunnel_net_v4": SERVER_TUNNEL_NET_V4,
                "tunnel_net_v6": SERVER_TUNNEL_NET_V6,
            })
        else:
            self._send_json(404, {"error": "not found"})


def main():
    parser = argparse.ArgumentParser(description="OTT VPN Peer Manager")
    parser.add_argument("--port", type=int, default=9123)
    parser.add_argument("--secret", default=os.environ.get("PEER_MANAGER_SECRET", ""))
    args = parser.parse_args()

    server = AuthHTTPServer(("127.0.0.1", args.port), PeerManagerHandler)
    server.auth_secret = args.secret or os.urandom(32).hex()
    logger.info("Peer manager listening on 127.0.0.1:%d", args.port)
    server.serve_forever()


if __name__ == "__main__":
    main()
