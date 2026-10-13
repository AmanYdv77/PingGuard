"""
Centralised typed configuration settings for PingGuard.

Loads environment variables from `.env` or the environment, validates types and constraints,
and provides computed database connection strings for both async (FastAPI)
and sync (Celery, Alembic) engines.
"""

import urllib.parse
from functools import lru_cache
from typing import Any, Literal

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

WEAK_PASSWORDS = {
    "password",
    "postgres",
    "admin",
    "root",
    "123456",
    "change-me",
    "change-me-generate-a-random-one",
}


class Settings(BaseSettings):
    """Application settings backed by environment variables and .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # 0. Environment Profile & Authentication
    environment: Literal["dev", "test", "prod"] = "dev"
    api_key: SecretStr
    cors_allowed_origins: list[str] | str = []

    # 1. Database Configuration
    database_url: str

    # 2. Redis Broker & Backend Configuration
    redis_broker_url: str = "redis://localhost:6379/0"
    redis_result_backend_url: str = "redis://localhost:6379/1"

    # 3. Celery Beat Periodic Sweep Frequency (seconds) & Batching
    sweep_interval_seconds: float = 15.0
    celerybeat_schedule_filename: str = "celerybeat-schedule"
    sweep_batch_size: int = 500
    sweep_max_batches: int = 20

    # 4. Network Resilience & HTTPX Prober Settings
    http_connect_timeout: float = 2.0
    http_read_timeout: float = 5.0
    http_write_timeout: float = 5.0
    http_pool_timeout: float = 2.0
    http_max_response_bytes: int = 1048576
    http_max_redirects: int = 5
    http_user_agent: str = "PingGuard/1.0"

    # 5. Probe Total Deadline & Celery Task Time Limits
    probe_total_timeout_seconds: float = 8.0
    celery_soft_time_limit: int = 10
    celery_hard_time_limit: int = 15

    # 6. Abuse Prevention & Resource Limits
    rate_limit_writes_per_minute: int = 60
    max_monitors: int = 100

    # 7. Data Retention & Maintenance
    ping_results_retention_days: int = 30
    retention_batch_size: int = 10000

    # 8. Structured Logging
    log_level: str = "INFO"
    log_json: bool = True

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: Any) -> str:
        """Validate log level string and normalize to uppercase."""
        if not isinstance(v, str):
            raise ValueError("log_level must be a string")
        norm = v.strip().upper()
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if norm not in valid_levels:
            raise ValueError(
                f"Invalid log level: {v}. Must be one of: {', '.join(sorted(valid_levels))}"
            )
        return norm

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, v: SecretStr) -> SecretStr:
        """Validate that api_key is at least 24 characters and not a weak placeholder."""
        val = v.get_secret_value()
        if len(val) < 24:
            raise ValueError("API_KEY must be at least 24 characters in length")
        if val.lower() in WEAK_PASSWORDS or val.lower().startswith("change-me"):
            raise ValueError("API_KEY cannot be a known weak or placeholder value")
        return v

    @field_validator("cors_allowed_origins", mode="after")
    @classmethod
    def parse_and_validate_cors_origins(cls, v: Any) -> list[str]:
        """
        Parses comma-separated string into origin list, rejects wildcards,
        and validates that each entry is a valid http/https origin with no path.
        """
        if v is None or v == "":
            return []
        if isinstance(v, str):
            raw_origins = [item.strip() for item in v.split(",") if item.strip()]
        elif isinstance(v, list | tuple | set):
            raw_origins = [str(item).strip() for item in v if str(item).strip()]
        else:
            raise ValueError(
                "CORS_ALLOWED_ORIGINS must be a comma-separated string or list of origins"
            )

        validated: list[str] = []
        for origin in raw_origins:
            if origin in ("*", "'*'", '"*"'):
                raise ValueError(
                    "Wildcard origin '*' is not allowed in CORS_ALLOWED_ORIGINS. "
                    "Specify explicit origin URLs (e.g. http://localhost:3000)."
                )
            clean_origin = origin.rstrip("/")
            parsed = urllib.parse.urlsplit(clean_origin)
            if parsed.scheme.lower() not in ("http", "https"):
                raise ValueError(
                    f"Invalid CORS origin scheme: '{origin}'. "
                    "Only HTTP and HTTPS origins are permitted."
                )
            if not parsed.netloc:
                raise ValueError(
                    f"Invalid CORS origin: '{origin}'. Must include a host/authority (e.g. http://localhost:3000)."
                )
            if parsed.path:
                raise ValueError(
                    f"CORS origin '{origin}' must not contain a path. Specify origin only (e.g. {parsed.scheme}://{parsed.netloc})."
                )
            if parsed.query or parsed.fragment:
                raise ValueError(
                    f"CORS origin '{origin}' must not contain query parameters or fragments."
                )
            normalized = f"{parsed.scheme.lower()}://{parsed.netloc}"
            if normalized not in validated:
                validated.append(normalized)

        return validated

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str | None) -> str:
        """Validate that database_url is provided and parses into a valid SQLAlchemy URL."""
        if not v or not isinstance(v, str) or not v.strip():
            raise ValueError("DATABASE_URL must be provided and non-empty")
        try:
            url = make_url(v)
            if not url.database:
                raise ValueError("DATABASE_URL must include a database name")
        except Exception as e:
            raise ValueError(f"Invalid DATABASE_URL: {e}") from e
        return v.strip()

    @field_validator(
        "sweep_interval_seconds",
        "http_connect_timeout",
        "http_read_timeout",
        "http_write_timeout",
        "http_pool_timeout",
        "probe_total_timeout_seconds",
    )
    @classmethod
    def validate_positive_float(cls, v: float) -> float:
        """Validate that timeout and interval values are strictly positive."""
        if v <= 0:
            raise ValueError("Timeout and interval values must be greater than zero")
        return v

    @field_validator(
        "http_max_response_bytes",
        "celery_soft_time_limit",
        "celery_hard_time_limit",
        "rate_limit_writes_per_minute",
        "max_monitors",
        "ping_results_retention_days",
        "retention_batch_size",
        "sweep_batch_size",
        "sweep_max_batches",
    )
    @classmethod
    def validate_positive_int(cls, v: int) -> int:
        """Validate that integer values are strictly positive."""
        if v <= 0:
            raise ValueError("Value must be greater than zero")
        return v

    @field_validator("http_max_redirects")
    @classmethod
    def validate_max_redirects(cls, v: int) -> int:
        """Validate that redirect count is between 0 and 20."""
        if not (0 <= v <= 20):
            raise ValueError("http_max_redirects must be between 0 and 20")
        return v

    @model_validator(mode="after")
    def validate_timeout_budget(self) -> "Settings":
        """
        Validate that probe total timeout and Celery time limits align.

        Requires:
        - celery_soft_time_limit >= probe_total_timeout_seconds + 2
        - celery_hard_time_limit >= celery_soft_time_limit + 3
        """
        if self.celery_soft_time_limit < self.probe_total_timeout_seconds + 2:
            raise ValueError(
                f"celery_soft_time_limit ({self.celery_soft_time_limit}) must be at least "
                f"probe_total_timeout_seconds + 2 ({self.probe_total_timeout_seconds + 2:.1f})"
            )
        if self.celery_hard_time_limit < self.celery_soft_time_limit + 3:
            raise ValueError(
                f"celery_hard_time_limit ({self.celery_hard_time_limit}) must be at least "
                f"celery_soft_time_limit + 3 ({self.celery_soft_time_limit + 3})"
            )
        return self

    @model_validator(mode="after")
    def validate_db_password(self) -> "Settings":
        """Reject default or weak database passwords when environment is prod."""
        if self.environment == "prod":
            url = make_url(self.database_url)
            pwd = url.password
            if not pwd or pwd.lower() in WEAK_PASSWORDS or pwd.lower().startswith("change-me"):
                raise ValueError(
                    f"Production environment rejects default or weak database password: '{pwd}'. "
                    "Set a strong random password in .env."
                )
        return self

    @property
    def async_database_url(self) -> str:
        """Return the database URL normalized to the postgresql+asyncpg driver for AsyncEngine."""
        url = make_url(self.database_url)
        return url.set(drivername="postgresql+asyncpg").render_as_string(hide_password=False)

    @property
    def sync_database_url(self) -> str:
        """Return database URL normalized to psycopg2 driver for sync Engine / Alembic."""
        url = make_url(self.database_url)
        return url.set(drivername="postgresql+psycopg2").render_as_string(hide_password=False)


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()  # type: ignore[call-arg]  # pydantic-settings loads required fields dynamically from environment/.env
