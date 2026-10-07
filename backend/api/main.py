from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse

from backend.api.routers import auth, servers, vpn, health
from backend.api.database import init_db, create_all_tables

app = FastAPI(
    title="OTT VPN Backend API",
    description="VPN backend providing Indian WireGuard gateways for legitimate OTT access.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to known client origins in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(servers.router)
app.include_router(vpn.router)
app.include_router(health.router)


@app.on_event("startup")
async def startup() -> None:
    init_db()
    await create_all_tables()


@app.get("/")
async def root():
    return RedirectResponse("/api/docs")


@app.get("/api")
async def api_info():
    return {
        "name": "OTT VPN API",
        "version": "1.0.0",
        "endpoints": {
            "auth": "/api/auth",
            "servers": "/api/servers",
            "vpn": "/api/vpn",
            "health": "/api/health",
        },
    }