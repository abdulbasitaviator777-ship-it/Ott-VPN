# OTT VPN — Architecture Design Document

## 1. Overview

OTT VPN is a production-grade VPN application providing secure, encrypted
tunnels to legitimate VPN gateways physically located in **India**.  When
connected, all IP traffic (full tunnel) is routed through an Indian
WireGuard gateway so the public source address becomes an Indian IP.

**Primary use case:** legitimate access to India-region content (ZEE5,
JioHotstar, SonyLIV, MX Player) for users who are legally entitled to
that content, subject to each service's own subscription and terms.

**Non-goals:** This software does **not** attempt to bypass DRM,
authentication, geo-blocking at the application/DRM layer, or any
anti-fraud/anti-bot security control of third-party services.  It only
provides standard encrypted IP routing.

---

## 2. Technology Choices

| Layer            | Choice                | Rationale                                                        |
|------------------|-----------------------|------------------------------------------------------------------|
| VPN Protocol     | WireGuard             | Modern audited cryptography, fast, simple config, wide support |
| Backend API      | FastAPI (Python 3.12) | Async, type-safe, auto OpenAPI docs, mature ecosystem            |
| Auth             | JWT + Argon2id        | Short-lived access tokens, refresh-token rotation, no stored hashes|
| Database         | PostgreSQL (16+)      | ACID, JSONB, geospatial via PostGIS, production proven           |
| Cache / Pub-Sub  | Redis 7+              | Real-time server health state, session caching                  |
| Migrations       | Alembic               | Versioned, reversible schema management                          |
| Server OS        | Ubuntu 22.04 LTS      | Long-term support, WireGuard in kernel                          |
| Containerisation | Docker + Compose      | Reproducible deployments                                        |
| IaC              | Terraform             | Cloud-agnostic, idempotent infra provisioning                   |
| DNS Resolver     | Unbound               | Recursive resolver with DNS-over-TLS upstreams, no query logging |
| Firewall         | UFW + iptables/nft    | Default-deny, WireGuard only, kill-switch integration            |
| Mobile (Android) | Kotlin + WG-Android   | Native NetworkExtension/VPN service                             |
| Mobile (iOS)     | Swift + NetworkExtension | NEVPNManager, AppConfig-based WireGuard                  |
| Mobile (shared)  | Python (Kivy/CLI)     | Cross-platform config consumer / CLI client                     |
| Testing          | pytest + pytest-asyncio, httpx, TestClient |                 |
| CI/CD            | GitHub Actions        | Lint, type-check, test, build, deploy                           |

### 2.1 Why WireGuard

1. **Modern cryptography** — uses only modern, audited primitives:
   ChaCha20-Poly1305 (AEAD), Curve25519, BLAKE2s, HKDF.
2. **Small codebase** — ~4 kLOC vs ~40 kLOC for OpenVPN, easier to
   audit and keep correct.
3. **High performance** — kernel implementation on Linux gives
   multi-gigabit throughput with low CPU.
4. **Simple configuration** — a peer needs only `PublicKey`,
   `AllowedIPs`, `Endpoint`, `PersistentKeepalive`, `PresharedKey`.
5. **Cross-platform** — official clients for Android, iOS, macOS,
   Windows, Linux; the config format is identical everywhere.
6. **No TLS handshake complexity** — the protocol is its own secure
   channel, reducing the attack surface.

The alternative (OpenVPN) is retained only as a documented fallback
for environments where WireGuard is blocked, but the default and
recommended protocol is WireGuard.

---

## 3. Network Architecture

```
                    ┌──────────────────────┐
                    │   Mobile / Desktop   │
                    │   OTT VPN Client     │
                    │  ├─ WireGuard tunnel │
                    │  ├─ Kill switch      │
                    │  ├─ DNS protection   │
                    │  └─ IPv6 protection  │
                    └──────────┬───────────┘
                               │  HTTPS (API auth)
                               ▼
                    ┌──────────────────────┐
                    │   Backend API        │
                    │  ├─ FastAPI          │
                    │  ├─ Auth (JWT)       │
                    │  ├─ Server mgmt      │
                    │  ├─ Config generation│
                    │  └─ Health monitor   │
                    └──┬─────────────┬─────┘
                       │ WireGuard   │ HTTPS
                       │ config      │ (health checks)
                       ▼             ▼
              ┌──────────────────┐  ┌────────────────┐
              │ Indian Gateway   │  │ Health worker  │
              │  ├─ WireGuard    │  │  ├─ curl/ipify │
              │  │  endpoint     │  │  ├─ traceroute │
              │  ├─ Unbound DNS  │  │  └─ ASN/geoloc │
              │  ├─ iptables     │  └────────────────┘
              │  └─ Kill-switch  │
              └────────┬─────────┘
                       │
                       ▼
               ┌───────────────┐
               │ Indian Internet│
               │ (ZEE5/JioHotstar)│
               └───────────────┘
```

### 3.1 WireGuard Topology

- **Deployment model:** hub-and-spokes.  Each Indian gateway is an
  independent WireGuard server (hub).  Clients connect as spokes.
  No client-to-client routing (peer traffic is disabled) so that
  users behind the same gateway cannot intercept each other's traffic.

- **Network:** Each gateway gets a `/24` IPv4 tunnel network
  (e.g. `10.66.0.0/24`) and a `/64` IPv6 subnet delegated from a
  Unique Local Address range (`fd86::/64`).  The gateway itself
  holds `.1`.

- **Peer management:** The backend generates an **ephemeral keypair
  per client device** at registration, stores only the public key on
  the server, and issues it to the client embedded in a signed
  WireGuard config.  No private server key ever leaves the gateway.

- **AllowedIPs:** `0.0.0.0/0, ::/0` (full tunnel) unless the user
  explicitly enables split-tunnel.

### 3.2 Data-flow summary

```
1. Client → POST /api/auth/register|login   (JWT issued)
2. Client → GET /api/servers               (India server list + keys)
3. Client → POST /vpn/config               (backend generates peer keypair,
                                            registers peer, returns signed .conf)
4. Client → WireGuard tunnel to gateway    (encrypted, Indian egress)
5. Gateway → Unbound DNS                   (no query logging)
6. Gateway → Internet                      (Indian source IP)
```

---

## 4. Database Schema

### 4.1 `users`

| Column          | Type        | Notes                          |
|-----------------|-------------|--------------------------------|
| id              | uuid PK     | primary key                    |
| email           | text US    | unique, lowercase              |
| password_hash   | text        | Argon2id                       |
| is_active       | boolean     | default true                   |
| plan_id         | uuid FK     | nullable (free tier)           |
| created_at      | timestamptz |                                |
| updated_at      | timestamptz |                                |
| last_login_at   | timestamptz | nullable                       |

### 4.2 `api_tokens` (refresh tokens)

| Column        | Type        | Notes                            |
|---------------|-------------|----------------------------------|
| id            | uuid PK     |                                  |
| user_id       | uuid FK     |                                  |
| token_hash    | text        | SHA-256 hash of token            |
| issued_at     | timestamptz |                                  |
| expires_at    | timestamptz |                                  |
| revoked_at    | timestamptz | nullable                         |
| replaced_by   | uuid FK SELF| for rotation chain               |
| device_info   | text        | user-agent / device name         |

### 4.3 `plans`

| Column      | Type    | Notes               |
|-------------|---------|---------------------|
| id          | uuid PK |                     |
| name        | text    | "Free", "Standard"  |
| max_devices | integer |                     |
| price_cents | integer |                     |

### 4.4 `servers`

| Column               | Type        | Notes                              |
|----------------------|-------------|------------------------------------|
| id                   | text PK     | `in-mum-01`                        |
| hostname             | text        | FQDN                               |
| country              | text        | "IN"                               |
| city                 | text        | "Mumbai"                           |
| region               | text        | "Maharashtra"                      |
| latitude             | numeric     |                                    |
| longitude            | numeric     |                                    |
| ipv4                 | inet        | public IPv4                        |
| ipv6                 | inet        | public IPv6                        |
| wireguard_pubkey     | text        | **public** key only                |
| wireguard_port       | integer     | e.g. 51820                         |
| wireguard_net        | cidr        | tunnel subnet                      |
| protocol             | text        | "wireguard"                        |
| capacity             | integer     | max concurrent peers               |
| status               | text        | healthy|degraded|offline        |
| last_health_check    | timestamptz |                                    |
| asn                  | bigint      | recorded from health check         |
| dns_ok               | boolean     |                                    |
| ipv6_ok              | boolean     |                                    |
| ott_zee5             | text        | pass|fail|unknown               |
| ott_jiohotstar       | text        | pass|fail|unknown                |
| ott_last_checked     | timestamptz |                                    |

### 4.5 `server_health` (time-series roll-up)

| Column        | Type        | Notes                          |
|---------------|-------------|--------------------------------|
| id            | uuid PK     |                                |
| server_id     | text FK     |                                |
| checked_at    | timestamptz |                                |
| latency_ms    | numeric     |                                |
| packet_loss   | numeric     | 0–100 percent                  |
| load_percent  | numeric     |                                |
| dns_leak      | boolean     | false = protected              |
| ipv6_leak     | boolean     | false = protected              |
| geolocated_in | boolean     | country == IN                  |
| detail        | jsonb       | raw check payload              |

### 4.6 `client_peers`

| Column         | Type        | Notes                          |
|----------------|-------------|--------------------------------|
| id             | uuid PK     |                                |
| user_id        | uuid FK     |                                |
| server_id      | text FK     |                                |
| public_key     | text        | client public key              |
| allowed_ips    | text        | `0.0.0.0/0, ::/0`              |
| tunnel_ip      | inet        | assigned .2+                   |
| tunnel_ip6     | inet        |                                |
| preshared_key  | text        | base64                         |
| created_at     | timestamptz |                                |
| expires_at     | timestamptz |                                |
| revoked        | boolean     |                                |
| last_handshake | timestamptz | nullable                      |

---

## 5. Security Model

### 5.1 Authentication

- Passwords hashed with **Argon2id** (memory-hard, resistant to GPU
  brute-force).
- Login returns a **short-lived access token** (JWT, 15 min) +
  **refresh token** (7 days, stored as SHA-256 hash).
- Refresh tokens use **rotation**: each refresh issues a new token
  and invalidates the previous one.  Reuse of a revoked token triggers
  full account token revocation (detection of token theft).
- Access tokens are validated by FastAPI dependency injection on
  every protected route.

### 5.2 API security

- TLS 1.3 everywhere (let's encrypt certbot on backend).
- Rate limiting via Redis (token-bucket per IP + per user).
- API inputs validated by Pydantic.
- No private key material in source or DB.  Server private keys live
  only on the gateway, generated at deploy time via `wg genkey`.

### 5.3 WireGuard security

- **Key rotation:** client peer keys rotate every 30 days.
- **PresharedKey:** every client receives a random PSK for
  additional symmetric protection of the handshake.
- **PersistentKeepalive:** 25 s (for NAT traversal behind CGNAT
  home routers).
- **MTU:** 1280 (IPv6 minimum, works over most ISPs without
  fragmentation).
- **Firewall:** only UDP 51820 exposed; default-deny inbound.

### 5.4 Kill switch

- Linux gateway: `iptables -A OUTPUT ! -o wg0` rule on client or
  platform VPN-on-TAP.
- Mobile (Android): `VpnService.Builder.addAllowed`/`block` +
  default-route routing.
- Mobile (iOS): `NETetherality`/NEVPNManager sets tunnel as default
  route.

### 5.5 DNS leak protection

- Client pushes DNS to gateway.
- Gateway runs **Unbound** with `harden-glue: yes`,
  `harden-dnssec-stripped: yes`, only DNS-over-TLS upstreams.
- `query-logging: no` — no DNS query persistence.
- `/etc/resolv.conf` on the tunnel points to `10.66.0.1`.

### 5.6 IPv6 leak protection

- Either full IPv6 routing through WireGuard (`AllowedIPs = ::/0`)
  or IPv6 disabled at the client platform level while connected.
- Gateway blocks outbound IPv6 traffic that does not egress via the
  tunnel.

---

## 6. Privacy Policy (logged data)

| Data              | Collected? | Retention            | Purpose                |
|-------------------|------------|----------------------|------------------------|
| Browsing history  | No         | —                    | —                      |
| DNS queries       | No         | —                    | —                      |
| Destination URLs   | No         | —                    | —                      |
| Page contents     | No         | —                    | —                      |
| Public IP (gateway)| Yes      | 30 days (aggregated) | Abuse prevention, health|
| Connection timestamp| Yes      | 30 days              | Reliability stats      |
| User email        | Yes        | Until account delete | Auth, billing          |
| Password hash     | Yes        | Argon2id, never plain| Auth                   |
| Peer public key   | Yes        | 30 days after revoke | Peer management        |

No traffic content is ever inspected or stored.

---

## 7. Implementation Roadmap

| Phase | Name                          | Duration | Key deliverable                              |
|-------|-------------------------------|----------|----------------------------------------------|
| 1     | Architecture & repo skeleton  | 1 day    | This doc, project structure, Alembic models  |
| 2     | Backend API                   | 3 days   | FastAPI: auth, servers, config, health       |
| 3     | One WireGuard gateway         | 2 days   | Server config script, Docker, firewall       |
| 4     | VPN client (CLI/Python)       | 3 days   | Config fetch, TUN, WireGuard handshake       |
| 5     | DNS + IPv6 protection         | 2 days   | Unbound config, IPv6 blocking, leak tests    |
| 6     | Kill switch                   | 2 days   | iptables-based, mobile VpnService            |
| 7     | Health monitoring             | 2 days   | Geolocation verification, latency, DNS leak  |
| 8     | Multiple Indian servers       | 1 day    | Terraform for Mumbai/Delhi/Hyd/BLR           |
| 9     | Auto server selection         | 2 days   | Scoring algorithm, recommended endpoint    |
| 10    | OTT compatibility dashboard   | 2 days   | Dashboard UI, test results, status badges    |
| 11    | Security testing              | 2 days   | Leak tests, auth tests, rate-limit tests     |
| 12    | Production deployment         | 2 days   | CI/CD, Terraform, Docker Compose production  |

---

## 8. Remaining Problems (Phase 1)

1. **Windows development host** — WireGuard kernel driver + TUN
   creation is only fully testable on Linux.  The CLI client uses
   `wg` userspace tools; full integration testing requires a Linux
   runner or Docker.
2. **No real Indian VPS yet** — the infrastructure is defined via
   Terraform but provisioning requires cloud credentials (AWS/Azure
   with Indian regions) that are not available in this environment.
3. **OTT test probes** — automated checks against ZEE5/JioHotstar
   require authenticated sessions; the design uses headless probes
   that detect "geo-blocked / requires subscription" without
   bypassing it.
4. **iOS/macOS entitlement** — building the native client requires
   Apple developer accounts and signed WireGuard frameworks.
