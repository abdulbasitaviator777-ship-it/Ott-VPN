from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    debug: bool = False

    # Database
    database_url: str = "sqlite+aiosqlite:///./ottvpn_dev.db"
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_prefix: str = "ottvpn:"

    # JWT
    secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Argon2id
    argon2_time_cost: int = 3
    argon2_memory_cost: int = 65536
    argon2_parallelism: int = 4

    # Rate limiting
    rate_limit_login: str = "5/minute"
    rate_limit_api: str = "1000/minute"

    # WireGuard
    wg_default_address_pool: str = "10.66.0.0/24"
    wg_default_address_pool6: str = "fd86::/64"
    wg_persistent_keepalive: int = 25
    wg_mtu: int = 1280
    client_config_expiry_hours: int = 24
    peer_key_rotate_days: int = 30

    # DNS
    dns_upstream_tls: str = "1.1.1.1@853,1.0.0.1@853"
    dns_upstream_in: str = "208.67.222.222@853,208.67.220.220@853"

    # GeoIP
    geoip_license_key: str = ""

    # OTT probes
    ott_probe_enabled: bool = False


settings = Settings()
