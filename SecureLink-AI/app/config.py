"""
SecureLink AI — Application Configuration

Loads all settings from environment variables (via .env file in development).
No secrets are hardcoded here. Uses pydantic-settings for validation.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Telegram ──────────────────────────────────────────────────────────────
    telegram_bot_token: str = ""
    webhook_url: str = ""  # If set, uses webhook mode; else polling

    # ── Threat Intel APIs ─────────────────────────────────────────────────────
    virustotal_api_key: str = ""
    google_safe_browsing_key: str = ""
    urlscan_api_key: str = ""
    phishtank_api_key: str = ""  # Optional — skipped gracefully if absent

    # ── Database ──────────────────────────────────────────────────────────────
    database_path: str = "./data/securelink.db"

    # ── Cache ─────────────────────────────────────────────────────────────────
    cache_ttl_hours: int = 24

    # ── Rate limiting ─────────────────────────────────────────────────────────
    rate_limit_cooldown: int = 10  # seconds between submissions per user

    # ── Server ────────────────────────────────────────────────────────────────
    port: int = 8000
    log_level: str = "INFO"

    # ── Model paths ───────────────────────────────────────────────────────────
    model_path: str = "./models/model.pkl"
    scaler_path: str = "./models/scaler.pkl"
    model_metadata_path: str = "./models/model_metadata.json"

    # ── Scoring weights (fixed, documented — not learned from live API data) ──
    # See inference.py for rationale.
    weight_ml: float = 0.50
    weight_vt: float = 0.25
    weight_sb: float = 0.15
    weight_rule: float = 0.10

    # ── Derived properties ────────────────────────────────────────────────────
    @property
    def database_url(self) -> str:
        """SQLAlchemy-compatible database URL."""
        db_path = Path(self.database_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{db_path.resolve()}"

    @property
    def is_production(self) -> bool:
        """True when running in webhook/production mode."""
        return bool(self.webhook_url)

    @property
    def has_virustotal(self) -> bool:
        return bool(self.virustotal_api_key)

    @property
    def has_safe_browsing(self) -> bool:
        return bool(self.google_safe_browsing_key)

    @property
    def has_urlscan(self) -> bool:
        return bool(self.urlscan_api_key)

    @property
    def has_phishtank(self) -> bool:
        return bool(self.phishtank_api_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the cached settings singleton."""
    return Settings()


def configure_logging(settings: Settings | None = None) -> None:
    """Configure root logger based on settings."""
    if settings is None:
        settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
