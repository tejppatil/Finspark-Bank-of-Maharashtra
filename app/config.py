"""Application configuration via pydantic settings."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Prahari runtime settings, loaded from environment / .env."""

    app_name: str = "Prahari"
    debug: bool = False
    database_url: str = "sqlite:///./prahari.db"
    host: str = "127.0.0.1"
    port: int = 8000
    # Auth. Override PRAHARI_SECRET_KEY in production; this default is demo-only.
    secret_key: str = "prahari-demo-secret-change-me"
    token_ttl_minutes: int = 480
    demo_password: str = "prahari123"  # shared password for all seeded accounts (demo)
    mfa_code: str = "246810"           # accepted step-up MFA code (demo)
    checkout_ttl_seconds: int = 300    # credential checkout lease (PAM vault workflow)
    checkout_risk_ceiling: float = 70  # session risk at/above this is refused checkout
    jit_max_minutes: int = 60          # longest just-in-time elevation grant
    # Anchor live portal events to business hours when run outside 09:00-17:00,
    # so a legitimate evening demo isn't spuriously flagged after-hours. Off in prod.
    demo_business_clock: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_prefix="PRAHARI_")


settings = Settings()
