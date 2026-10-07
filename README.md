# OTT VPN

**OTT VPN** — A production-grade VPN application that routes traffic
through legitimate WireGuard gateways hosted in **India**, enabling
Indian public IP addressing for legally accessible India-region OTT
services (ZEE5, JioHotstar, SonyLIV, MX Player, etc.).

> This software provides **encrypted IP routing only**.  It does **not**
> bypass DRM, authentication, subscription requirements, or any
> anti-fraud/security controls of third-party services.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design:
WireGuard hub-and-spokes topology, FastAPI backend with JWT + Argon2id,
PostgreSQL, Redis, controlled Unbound DNS, kill-switch, DNS/IPv6 leak
protection, and automated health/geolocation verification.

## Quick Start

```bash
# 1. Copy environment
cp .env.example .env
#    edit .env — set SECRET_KEY, DATABASE_URL, REDIS_URL

# 2. API-only smoke test (no DB needed)
python -m uvicorn backend.api.main:app --reload

# 3. Run the backend test-suite
python -m pytest tests/ -v

# 4. (Linux) Generate a dev WireGuard server config
python vpn-server/wireguard/generate_server_config.py --country IN --city Mumbai

# 5. (Linux) Health-check an Indian gateway
python backend/health/checks.py --server-id in-mum-01
```

## Project Layout

```
india-vpn/
├── backend/
│   ├── api/      # FastAPI application, routers, schemas
│   ├── auth/     # JWT, Argon2id, token rotation
│   ├── vpn/      # WireGuard config generation, peer registration
│   ├── servers/  # Server CRUD, selection, metadata
│   ├── health/   # Health checks, geolocation, leak tests
│   └── tests/    # pytest suite
├── vpn-server/
│   ├── wireguard/
│   ├── firewall/
│   ├── dns/
│   └── monitoring/
├── mobile/
│   ├── android/   # Kotlin + WireGuard Android API
│   ├── ios/       # Swift + NetworkExtension
│   └── shared/    # API client, config model, CLI client
├── infrastructure/
│   ├── terraform/
│   └── docker/
├── tests/
├── docs/
├── .env.example
└── README.md
```

## Phases

| Phase | Status      |
|-------|-------------|
| 1. Architecture | Design |
| 2. Backend API  | Pending |
| 3. WireGuard server | Pending |
| 4. VPN client   | Pending |
| … | Pending |

## License

This project is provided for educational and legitimate VPN use only.
