"""
PingGuard Schemas.

Defines the core Pydantic v2 data contracts for incoming requests and outgoing responses.
"""

import ipaddress
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from app.enums import MonitorStatus
from app.ssrf import is_ip_blocked


class MonitorCreate(BaseModel):
    """
    Request contract for creating a new monitored endpoint.

    Validated strictly at the API perimeter before any persistence or scheduling.
    """

    name: str = Field(
        ...,
        min_length=1,
        max_length=120,
        description="Human-readable label or service name for the monitor.",
        examples=["Customer Portal API", "Primary Marketing Website"],
    )
    url: HttpUrl = Field(
        ...,
        description=(
            "Target HTTP or HTTPS URL to monitor. Validated structurally via HttpUrl. "
            "NOTE: Strict network/SSRF egress validation (private/link-local IP blocking) "
            "is enforced by the probe execution engine."
        ),
        examples=["https://status.github.com", "https://api.stripe.com/health"],
    )
    check_interval_seconds: int = Field(
        default=60,
        ge=15,
        le=86400,
        description="Evaluation interval in seconds. Minimum 15s, maximum 86400s (24h).",
        examples=[30, 60, 300],
    )

    @field_validator("url")
    @classmethod
    def validate_url_scheme_and_safety(cls, v: HttpUrl) -> HttpUrl:
        scheme = v.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(
                f"URL scheme '{scheme}' is forbidden. Only 'http' and 'https' are allowed."
            )
        if v.username or v.password:
            raise ValueError(
                "Credential-bearing URLs (user:password@) are forbidden for security reasons."
            )
        host = (v.host or "").strip().lower()
        if host in ("localhost", "localhost.localdomain"):
            raise ValueError(
                f"SSRF security violation: '{host}' is a forbidden loopback destination."
            )
        try:
            ip_obj = ipaddress.ip_address(host)
            if is_ip_blocked(ip_obj):
                raise ValueError(
                    f"SSRF security violation: IP literal '{host}' is private or restricted."
                )
        except ValueError as err:
            if "SSRF security violation" in str(err):
                raise
        return v


class MonitorRead(BaseModel):
    """
    Response contract representing a registered monitor.

    Configured with from_attributes=True to serialize SQLAlchemy ORM model instances directly.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique sequential identifier for the monitor.")
    name: str = Field(..., description="Human-readable monitor name.")
    url: HttpUrl = Field(..., description="Target URL being monitored.")
    check_interval_seconds: int = Field(..., description="Scheduled probe frequency in seconds.")
    status: MonitorStatus = Field(..., description="Current health status of the endpoint.")
    last_checked_at: datetime | None = Field(
        default=None,
        description=(
            "UTC timestamp of the most recent probe execution (None if pending initial check)."
        ),
    )
    next_check_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the monitor is next eligible for scheduler sweep.",
    )


class PingResultRead(BaseModel):
    """
    Response contract representing an individual probe execution.
    """

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Unique sequential identifier for the result.")
    monitor_id: int = Field(..., description="Foreign key ID of the parent monitor.")
    status_code: int | None = Field(
        default=None,
        description="HTTP status code returned by target, or None if connection failed.",
    )
    latency_ms: float | None = Field(
        default=None, description="Round-trip latency in milliseconds."
    )
    error: str | None = Field(
        default=None, description="Error classification string if the probe encountered an issue."
    )
    checked_at: datetime = Field(..., description="UTC timestamp of the probe execution.")


class MonitorCheckResponse(BaseModel):
    """
    Response model for an asynchronous monitor check request.
    """

    status: str = Field(default="queued", description="Dispatch status of the probe task.")
    monitor_id: int = Field(
        ..., description="Unique integer ID of the monitor queued for checking."
    )


class MonitorUpdate(BaseModel):
    """
    Request contract for updating an existing monitor's configuration.

    Only fields explicitly provided are updated. Target URL modifications are
    deliberately excluded to maintain historical telemetry integrity.
    """

    name: str | None = Field(
        default=None,
        min_length=1,
        max_length=120,
        description="Updated display name. Omit or pass null to leave unchanged.",
    )
    check_interval_seconds: int | None = Field(
        default=None,
        ge=15,
        le=86400,
        description="Updated check interval in seconds. Omit or pass null to leave unchanged.",
    )
