"""
SQLAlchemy 2.0 Typed ORM Models.

Defines the relational schema for Monitor configurations and PingResult logs.
"""

from datetime import UTC, datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.enums import MonitorStatus


class Base(DeclarativeBase):
    """Base declarative class for all PingGuard ORM models."""

    pass


class Monitor(Base):
    """
    Durable configuration and state for an endpoint monitor.

    Stores user-configured polling schedules and future scheduler tick timestamps (next_check_at).
    """

    __tablename__ = "monitors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )  # Intentionally not unique (same URL may have multiple configs)
    check_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default=MonitorStatus.PENDING.value, nullable=False
    )

    # Timezone-aware scheduling timestamps (UTC)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    # Relationship to telemetry logs with cascade deletion
    results: Mapped[list["PingResult"]] = relationship(
        "PingResult",
        back_populates="monitor",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('up', 'degraded', 'down', 'pending')",
            name="ck_monitors_status",
        ),
    )


class PingResult(Base):
    """
    Historical execution record for a single probe check.
    """

    __tablename__ = "ping_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    monitor_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("monitors.id", ondelete="CASCADE"),
        nullable=False,
    )
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
        index=True,
    )

    # Back-reference to parent monitor
    monitor: Mapped[Monitor] = relationship("Monitor", back_populates="results")

    __table_args__ = (Index("idx_ping_results_monitor_checked", "monitor_id", "checked_at"),)
