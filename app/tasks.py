"""
Distributed Task Definitions.

Defines Celery background tasks:
- `execute_ping`: HTTP health probe, latency recording, and monitor status updates.
- `sweep_due_monitors`: Periodic scheduler sweep dispatching due health checks.
- `prune_ping_results`: Retention pruning of old telemetry data.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from celery.exceptions import SoftTimeLimitExceeded
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_sync_db
from app.enums import PingOutcome
from app.models import Monitor, PingResult
from app.net import (
    PingResultDTO,
    robust_ping,
)
from app.status import outcome_to_status
from app.worker import celery_app

logger = logging.getLogger(__name__)

# Transient network failure error codes eligible for Celery worker retry
TRANSIENT_ERRORS: tuple[str, ...] = (
    "connect_timeout",
    "read_timeout",
    "write_timeout",
    "pool_timeout",
    "total_timeout",
    "connect_error",
)


def save_ping_result(
    session: Session,
    monitor_id: int,
    status_code: int | None,
    latency_ms: float | None,
    error: str | None,
    checked_at: datetime,
) -> PingResult:
    """
    Persists a telemetry result row to the database.
    """
    result = PingResult(
        monitor_id=monitor_id,
        status_code=status_code,
        latency_ms=latency_ms,
        error=error,
        checked_at=checked_at,
    )
    session.add(result)
    return result


def _run_probe_task(
    task: Any,
    monitor_id: int,
    *,
    probe: Callable[[Monitor], PingResultDTO],
    update_monitor_status: bool = True,
) -> dict[str, Any]:
    """
    Shared core execution harness for Celery network probe tasks.
    Handles DB session lifecycle, probe execution, telemetry persistence,
    status updates, exponential backoff retries, and soft time limit recovery.
    """
    logger.info("Starting ping monitor_id=%s", monitor_id)

    try:
        with get_sync_db() as session:
            monitor = session.get(Monitor, monitor_id)
            if monitor is None:
                logger.warning("Monitor not found for execute_ping monitor_id=%s", monitor_id)
                return {"status": "not_found", "monitor_id": monitor_id}

            if not monitor.url:
                logger.error("Ping failed monitor_id=%s reason=missing_url", monitor_id)
                return {"status": "error", "reason": "missing_url", "monitor_id": monitor_id}

            now = datetime.now(UTC)

            dto = probe(monitor)

            if update_monitor_status:
                monitor.status = outcome_to_status(dto.outcome).value
                monitor.last_checked_at = now

            save_ping_result(
                session=session,
                monitor_id=monitor_id,
                status_code=dto.status_code,
                latency_ms=dto.latency_ms,
                error=dto.error_detail,
                checked_at=now,
            )

            logger.info(
                "Ping completed monitor_id=%s outcome=%s status_code=%s latency_ms=%s error=%s",
                monitor_id,
                dto.outcome.value,
                dto.status_code,
                dto.latency_ms,
                dto.error_detail,
            )

            if dto.error_detail in TRANSIENT_ERRORS and task.request.retries < task.max_retries:
                countdown = 2**task.request.retries
                logger.warning(
                    "Transient network error on monitor_id=%s (%s). "
                    "Retrying in %ss (attempt %s/%s)...",
                    monitor_id,
                    dto.error_detail,
                    countdown,
                    task.request.retries + 1,
                    task.max_retries,
                )
                raise task.retry(exc=Exception(dto.error_detail), countdown=countdown)

            return {
                "status": "completed",
                "monitor_id": monitor_id,
                "outcome": dto.outcome.value,
                "status_code": dto.status_code,
                "latency_ms": dto.latency_ms,
                "error": dto.error_detail,
                "final_url": dto.final_url,
            }

    except SoftTimeLimitExceeded:
        logger.error("Soft time limit exceeded in execute_ping for monitor_id=%s", monitor_id)
        now = datetime.now(UTC)
        with get_sync_db() as recovery_session:
            mon = recovery_session.get(Monitor, monitor_id)
            if mon:
                mon.status = outcome_to_status(PingOutcome.DOWN).value
                mon.last_checked_at = now
            save_ping_result(
                session=recovery_session,
                monitor_id=monitor_id,
                status_code=None,
                latency_ms=None,
                error="task_soft_time_limit",
                checked_at=now,
            )
        return {
            "status": "completed",
            "monitor_id": monitor_id,
            "outcome": PingOutcome.DOWN.value,
            "status_code": None,
            "latency_ms": None,
            "error": "task_soft_time_limit",
            "final_url": None,
        }


@celery_app.task(
    bind=True,
    name="app.tasks.execute_ping",
    max_retries=3,
    default_retry_delay=2,
)
def execute_ping(self, monitor_id: int) -> dict[str, Any]:
    """
    Executes an uptime health probe for the specified monitor.

    - Uses shared `robust_ping` powered by httpx.AsyncClient.
    - Enforces SSRF defense, DNS rebinding checks, and redirect interception.
    - Classifies outcomes into UP, DEGRADED, DOWN, UNREACHABLE.
    - Retries only transient network timeouts/errors with exponential backoff.
    - Never retries SSRF-blocked destinations or TLS configuration errors.
    - Persists historical telemetry to 'ping_results' with check_type='monitor'.
    - Updates Monitor.status ('up', 'degraded', 'down') and last_checked_at.
    """
    return _run_probe_task(
        self,
        monitor_id,
        probe=lambda m: robust_ping(m.url),
        update_monitor_status=True,
    )


# =========================================================================
# Celery Beat Periodic Scheduling Heartbeat
# =========================================================================


@celery_app.task(
    bind=True,
    name="app.tasks.sweep_due_monitors",
    ignore_result=True,
)
def sweep_due_monitors(
    self,
    batch_size: int | None = None,
    max_batches: int | None = None,
) -> dict[str, int]:
    """
    Celery Beat Scheduling Heartbeat.

    Decides WHEN health probes and keep-alive activities are due and enqueues them.
    Adheres strictly to the PingGuard architectural separation:
    - Beat/Sweep decides WHEN to check.
    - Celery Workers decide HOW to check.
    - Zero outbound HTTP requests are performed within this task.
    - Batch-based bounded querying (sweep_batch_size, sweep_max_batches).
    - Concurrency-safe claiming via SELECT ... FOR UPDATE SKIP LOCKED.
    - Advance-and-commit BEFORE enqueueing to prevent duplicates.
    - Task expiration passed to apply_async (expires=interval) to discard stale tasks.
    - Automatic broker-error recovery: resets next_check_at to now in a new transaction.
    - Two independent schedules: monitoring (next_check_at) and keep-alive (next_keep_alive_at).
    """
    settings = get_settings()
    b_size = batch_size if batch_size is not None else settings.sweep_batch_size
    m_batches = max_batches if max_batches is not None else settings.sweep_max_batches
    now = datetime.now(UTC)
    logger.info(
        "Scheduler sweep started at %s (batch_size=%d, max_batches=%d)",
        now.isoformat(),
        b_size,
        m_batches,
    )

    monitors_enqueued = 0

    for _ in range(m_batches):
        batch_items: list[tuple[int, int]] = []
        with get_sync_db() as session:
            due_monitors = (
                session.query(Monitor)
                .filter(
                    Monitor.next_check_at <= now,
                )
                .order_by(Monitor.next_check_at.asc())
                .limit(b_size)
                .with_for_update(skip_locked=True)
                .all()
            )
            if not due_monitors:
                break

            for monitor in due_monitors:
                monitor.next_check_at = now + timedelta(seconds=monitor.check_interval_seconds)
                batch_items.append((monitor.id, monitor.check_interval_seconds))

            session.commit()

        # Enqueue only AFTER the claim is committed
        failed_ids: list[int] = []
        for idx, (m_id, interval) in enumerate(batch_items):
            try:
                execute_ping.apply_async(args=[m_id], expires=interval)
                monitors_enqueued += 1
                logger.info("Enqueued execute_ping monitor_id=%s with expires=%s", m_id, interval)
            except Exception as exc:
                logger.error(
                    "Failed to enqueue execute_ping monitor_id=%s: %s. Broker may be down.",
                    m_id,
                    exc,
                )
                failed_ids = [item[0] for item in batch_items[idx:]]
                break

        if failed_ids:
            try:
                with get_sync_db() as recovery_session:
                    recovery_session.query(Monitor).filter(Monitor.id.in_(failed_ids)).update(
                        {Monitor.next_check_at: now},
                        synchronize_session=False,
                    )
                    recovery_session.commit()
                logger.info(
                    "Reset next_check_at to now for %d monitors due to broker error",
                    len(failed_ids),
                )
            except Exception as rec_exc:
                logger.critical("Failed to reset schedule during broker recovery: %s", rec_exc)
            break

    logger.info(
        "Scheduler sweep completed. Enqueued %d health pings.",
        monitors_enqueued,
    )
    return {
        "monitors_enqueued": monitors_enqueued,
    }


@celery_app.task(name="app.tasks.prune_ping_results", ignore_result=True, acks_late=True)
def prune_ping_results(batch_size: int | None = None) -> int:
    """
    Prunes ping_results older than ping_results_retention_days in small batches.
    Prevents unbounded table growth while avoiding long database table locks.
    """
    settings = get_settings()
    retention_days = settings.ping_results_retention_days

    batch_limit = batch_size if batch_size is not None else settings.retention_batch_size

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    total_deleted = 0

    with get_sync_db() as session:
        while True:
            subq = (
                select(PingResult.id)
                .where(PingResult.checked_at < cutoff)
                .order_by(PingResult.id)
                .limit(batch_limit)
                .scalar_subquery()
            )
            stmt = delete(PingResult).where(PingResult.id.in_(subq))
            result = session.execute(stmt)
            session.commit()

            deleted = int(
                result.rowcount  # type: ignore[attr-defined]  # CursorResult provides rowcount
            )
            total_deleted += deleted
            if deleted == 0:
                break

    logger.info(
        "Pruned %d expired ping_result rows older than %s", total_deleted, cutoff.isoformat()
    )
    return total_deleted
