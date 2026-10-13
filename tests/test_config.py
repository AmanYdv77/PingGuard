"""
Unit tests for centralised typed Settings in app.config.
"""

import pytest
from pydantic import ValidationError


def test_import_and_defaults(monkeypatch):
    """Verify Settings loads expected defaults with required database_url provided."""
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+asyncpg://postgres:pass@localhost:5432/pingguard"
    )
    from app.config import Settings

    settings = Settings()
    assert settings.database_url == "postgresql+asyncpg://postgres:pass@localhost:5432/pingguard"
    assert settings.redis_broker_url == "redis://localhost:6379/0"
    assert settings.redis_result_backend_url == "redis://localhost:6379/1"
    assert settings.sweep_interval_seconds == 15.0
    assert settings.http_connect_timeout == 2.0
    assert settings.http_read_timeout == 5.0
    assert settings.http_write_timeout == 5.0
    assert settings.http_pool_timeout == 2.0
    assert settings.http_max_response_bytes == 1048576
    assert settings.http_max_redirects == 5
    assert settings.http_user_agent == "PingGuard/1.0"


def test_env_var_overrides(monkeypatch):
    """Verify HTTP_* and other env vars from .env / docker-compose are respected."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
    monkeypatch.setenv("HTTP_CONNECT_TIMEOUT", "1.25")
    monkeypatch.setenv("HTTP_READ_TIMEOUT", "3.75")
    monkeypatch.setenv("HTTP_MAX_REDIRECTS", "10")
    monkeypatch.setenv("HTTP_USER_AGENT", "CustomProbe/2.0")
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "30.0")

    from app.config import Settings

    settings = Settings()
    assert settings.http_connect_timeout == 1.25
    assert settings.http_read_timeout == 3.75
    assert settings.http_max_redirects == 10
    assert settings.http_user_agent == "CustomProbe/2.0"
    assert settings.sweep_interval_seconds == 30.0


def test_http_connect_timeout_override(monkeypatch):
    """Verify with HTTP_CONNECT_TIMEOUT=1.0 set, get_settings().http_connect_timeout == 1.0."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
    monkeypatch.setenv("HTTP_CONNECT_TIMEOUT", "1.0")
    from app.config import get_settings

    get_settings.cache_clear()
    try:
        assert get_settings().http_connect_timeout == 1.0
    finally:
        get_settings.cache_clear()


def test_database_url_driver_properties():
    """Verify async and sync database URL translations."""
    from app.config import Settings

    # Case 1: postgresql://
    s1 = Settings(database_url="postgresql://usr:pwd@localhost:5432/dbname")
    assert s1.async_database_url.startswith("postgresql+asyncpg://")
    assert s1.sync_database_url.startswith("postgresql+psycopg2://")

    # Case 2: postgresql+asyncpg://
    s2 = Settings(database_url="postgresql+asyncpg://usr:pwd@localhost:5432/dbname")
    assert s2.async_database_url == "postgresql+asyncpg://usr:pwd@localhost:5432/dbname"
    assert s2.sync_database_url == "postgresql+psycopg2://usr:pwd@localhost:5432/dbname"

    # Case 3: postgresql+psycopg2://
    s3 = Settings(database_url="postgresql+psycopg2://usr:pwd@localhost:5432/dbname")
    assert s3.async_database_url == "postgresql+asyncpg://usr:pwd@localhost:5432/dbname"
    assert s3.sync_database_url == "postgresql+psycopg2://usr:pwd@localhost:5432/dbname"


def test_database_url_required():
    """Verify instantiating Settings without database_url raises ValidationError."""
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(_env_file=None, database_url=None)  # type: ignore[arg-type]  # Deliberately invalid type to test validation


def test_positive_timeout_validation():
    """Verify negative or zero timeout values raise ValidationError."""
    from app.config import Settings

    with pytest.raises(ValidationError):
        Settings(
            database_url="postgresql+asyncpg://u:p@localhost:5432/db",
            http_connect_timeout=-1.0,
        )

    with pytest.raises(ValidationError):
        Settings(
            database_url="postgresql+asyncpg://u:p@localhost:5432/db",
            sweep_interval_seconds=0.0,
        )

    with pytest.raises(ValidationError):
        Settings(
            database_url="postgresql+asyncpg://u:p@localhost:5432/db",
            http_max_redirects=-1,
        )

    with pytest.raises(ValidationError):
        Settings(
            database_url="postgresql+asyncpg://u:p@localhost:5432/db",
            http_max_redirects=21,
        )


def test_get_settings_cached(monkeypatch):
    """Verify get_settings returns a cached singleton instance."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@localhost:5432/db")
    from app.config import get_settings

    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


@pytest.mark.parametrize(
    "weak_url",
    [
        "postgresql+asyncpg://postgres:postgres@localhost:5432/pingguard",
        "postgresql+asyncpg://postgres:password@localhost:5432/pingguard",
        "postgresql+asyncpg://postgres:admin@localhost:5432/pingguard",
        "postgresql+asyncpg://postgres:root@localhost:5432/pingguard",
        "postgresql+asyncpg://postgres:123456@localhost:5432/pingguard",
        "postgresql+asyncpg://postgres:change-me-generate-a-random-one@localhost:5432/pingguard",
        "postgresql+asyncpg://postgres:@localhost:5432/pingguard",
    ],
)
def test_weak_passwords_rejected_in_prod(weak_url):
    """Verify production environment refuses known weak or placeholder passwords."""
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(database_url=weak_url, environment="prod")
    assert "password" in str(exc_info.value).lower()


def test_strong_password_allowed_in_prod():
    """Verify production environment accepts strong, random database passwords."""
    from app.config import Settings

    strong_url = (
        "postgresql+asyncpg://postgres:A9k_L2x0m-Pq8vY_Z4w7R1s9_X2j5@localhost:5432/pingguard"
    )
    settings = Settings(database_url=strong_url, environment="prod")
    assert settings.environment == "prod"


def test_weak_passwords_allowed_in_test_environment():
    """Verify test environment allows local test database passwords (e.g. testpass)."""
    from app.config import Settings

    test_url = "postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    settings = Settings(database_url=test_url, environment="test")
    assert settings.environment == "test"


# =============================================================================
# Task A8: Probe Total Timeout & Celery Limit Budget Tests
# =============================================================================


def test_probe_total_timeout_settings_defaults():
    """Verify probe total timeout and Celery time limits have expected defaults."""
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert s.probe_total_timeout_seconds == 8.0
    assert s.celery_soft_time_limit == 10
    assert s.celery_hard_time_limit == 15


def test_celery_soft_time_limit_too_low_raises():
    """Verify celery_soft_time_limit < probe_total_timeout_seconds + 2 raises ValidationError."""
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            probe_total_timeout_seconds=9.0,
            celery_soft_time_limit=10,
        )
    assert "celery_soft_time_limit" in str(exc_info.value)


def test_celery_hard_time_limit_too_low_raises():
    """Verify celery_hard_time_limit < celery_soft_time_limit + 3 raises ValidationError."""
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            celery_soft_time_limit=10,
            celery_hard_time_limit=12,
        )
    assert "celery_hard_time_limit" in str(exc_info.value)


def test_api_key_required(monkeypatch):
    """Verify omitting API_KEY raises ValidationError."""
    monkeypatch.delenv("API_KEY", raising=False)
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
        )
    assert "api_key" in str(exc_info.value)


def test_api_key_min_length(monkeypatch):
    """Verify API_KEY shorter than 24 characters raises ValidationError."""
    monkeypatch.setenv("API_KEY", "too-short-1234567890")
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
        )
    assert "at least 24 characters" in str(exc_info.value)


def test_api_key_weak_value_rejected(monkeypatch):
    """Verify known weak/placeholder API keys are rejected with ValidationError."""
    monkeypatch.setenv("API_KEY", "change-me-generate-a-random-one")
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
        )
    assert "weak or placeholder value" in str(exc_info.value)


def test_api_key_secret_str_safe_repr(monkeypatch):
    """Verify API key is wrapped in SecretStr and never leaks in repr or str."""
    secret = "a" * 32
    monkeypatch.setenv("API_KEY", secret)
    from app.config import Settings

    settings = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert settings.api_key.get_secret_value() == secret
    assert secret not in str(settings.api_key)
    assert secret not in repr(settings)


def test_cors_allowed_origins_wildcard_rejected(monkeypatch):
    """Verify wildcard '*' origin in CORS_ALLOWED_ORIGINS is rejected with ValidationError."""
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "*")
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
        )
    assert (
        "Wildcard" in str(exc_info.value)
        or "not allowed" in str(exc_info.value)
        or "not permitted" in str(exc_info.value)
    )


def test_cors_allowed_origins_parsing(monkeypatch):
    """Verify comma-separated origins are parsed into a normalized list."""
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000, https://app.example.com/")
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert s.cors_allowed_origins == ["http://localhost:3000", "https://app.example.com"]


def test_cors_allowed_origins_invalid_path_rejected(monkeypatch):
    """Verify origins containing paths are rejected."""
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000/api")
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
        )
    assert "path" in str(exc_info.value).lower()


def test_rate_limit_and_monitor_cap_defaults():
    """Verify rate_limit_writes_per_minute and max_monitors default values."""
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert s.rate_limit_writes_per_minute == 60
    assert s.max_monitors == 100


def test_rate_limit_and_monitor_cap_positive_validation():
    """Verify rate_limit_writes_per_minute and max_monitors reject zero or negative values."""
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            rate_limit_writes_per_minute=0,
        )
    assert "rate_limit_writes_per_minute" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            max_monitors=-5,
        )
    assert "max_monitors" in str(exc_info.value)


def test_retention_settings_defaults():
    """Verify ping_results_retention_days and retention_batch_size defaults."""
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert s.ping_results_retention_days == 30
    assert s.retention_batch_size == 10000


def test_retention_settings_validation():
    """Verify retention settings reject values less than 1."""
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            ping_results_retention_days=0,
        )
    assert "ping_results_retention_days" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            retention_batch_size=0,
        )
    assert "retention_batch_size" in str(exc_info.value)


# =============================================================================
# Task A17: Scheduler Sweep Batching & Throttling Settings Tests
# =============================================================================


def test_sweep_batching_settings_defaults():
    """Verify sweep_batch_size and sweep_max_batches defaults."""
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert s.sweep_batch_size == 500
    assert s.sweep_max_batches == 20


def test_sweep_batching_settings_validation():
    """Verify sweep batching settings reject non-positive integers."""
    from app.config import Settings

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            sweep_batch_size=0,
        )
    assert "sweep_batch_size" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            sweep_max_batches=0,
        )
    assert "sweep_max_batches" in str(exc_info.value)


def test_logging_settings_defaults():
    """Verify log_level and log_json have expected defaults."""
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
    )
    assert s.log_level == "INFO"
    assert s.log_json is True


def test_logging_settings_validation():
    """Verify log_level normalization and invalid value rejection."""
    from app.config import Settings

    s = Settings(
        database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
        log_level="warning",
        log_json=False,
    )
    assert s.log_level == "WARNING"
    assert s.log_json is False

    with pytest.raises(ValidationError) as exc_info:
        Settings(
            database_url="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test",
            log_level="NOT_A_LEVEL",
        )
    assert "log_level" in str(exc_info.value)
