"""
Domain Enumerations.

Central source of truth for monitor statuses, monitor execution modes,
and network probe outcomes across the application.
"""

from enum import StrEnum


class MonitorStatus(StrEnum):
    """
    Lifecycle and operational health state of a monitor.

    Persisted to PostgreSQL 'monitors.status' with CHECK constraint ck_monitors_status.
    """

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    PENDING = "pending"


class PingOutcome(StrEnum):
    """
    Classification outcome returned by the network prober.
    """

    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"
    UNREACHABLE = "unreachable"
