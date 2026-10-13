"""
Unit and integration tests for ping_results data retention and pruning.
"""

from datetime import UTC, datetime, timedelta

from app.db import get_sync_db
from app.models import Monitor, PingResult
from app.worker import celery_app
from celery.schedules import crontab
from sqlalchemy import func, select


def seed_ping_result(session, monitor_id: int, checked_at: datetime) -> int:
    """Helper to insert a ping_result directly into the test database."""
    res = PingResult(
        monitor_id=monitor_id,
        status_code=200,
        latency_ms=10.0,
        checked_at=checked_at,
    )
    session.add(res)
    session.commit()
    session.refresh(res)
    return res.id


def seed_monitor(session) -> int:
    """Helper to create a dummy monitor."""
    m = Monitor(
        name="Retention Test Monitor",
        url="https://retention.example.com",
        check_interval_seconds=60,
    )
    session.add(m)
    session.commit()
    session.refresh(m)
    return m.id


def test_beat_schedule_contains_retention_task():
    """Verify Celery Beat schedule contains prune_ping_results with daily crontab."""
    schedule = celery_app.conf.beat_schedule
    assert "prune-ping-results" in schedule or "prune_ping_results" in schedule
    entry = schedule.get("prune-ping-results") or schedule.get("prune_ping_results")
    assert entry["task"] == "app.tasks.prune_ping_results"
    assert entry["schedule"] == crontab(hour=3, minute=0)


def test_prune_ping_results_deletes_only_old_records():
    """Verify only rows older than cutoff (retention_days) are deleted."""
    from app.tasks import prune_ping_results

    with get_sync_db() as session:
        # Clean up
        session.query(PingResult).delete()
        session.query(Monitor).delete()
        session.commit()

        mid = seed_monitor(session)

        now = datetime.now(UTC)
        old_time = now - timedelta(days=35)
        new_time = now - timedelta(days=5)

        old_id = seed_ping_result(session, mid, old_time)
        new_id = seed_ping_result(session, mid, new_time)

    # Run the prune task
    deleted = prune_ping_results()
    assert deleted >= 1

    with get_sync_db() as session:
        remaining_ids = session.scalars(select(PingResult.id)).all()
        assert old_id not in remaining_ids
        assert new_id in remaining_ids


def test_prune_ping_results_batching_loop():
    """
    Verify batching: with 5 old rows and batch size 2,
    all 5 rows are pruned across multiple batches.
    """
    from app.tasks import prune_ping_results

    with get_sync_db() as session:
        session.query(PingResult).delete()
        session.query(Monitor).delete()
        session.commit()

        mid = seed_monitor(session)
        now = datetime.now(UTC)
        old_time = now - timedelta(days=40)

        for _ in range(5):
            seed_ping_result(session, mid, old_time)

    # Call with explicit batch_size=2
    deleted = prune_ping_results(batch_size=2)
    assert deleted == 5

    with get_sync_db() as session:
        count = session.scalar(select(func.count()).select_from(PingResult))
        assert count == 0


def test_prune_ping_results_empty_table_noop():
    """Running retention pruning on an empty table safely deletes 0 rows."""
    from app.tasks import prune_ping_results

    with get_sync_db() as session:
        session.query(PingResult).delete()
        session.query(Monitor).delete()
        session.commit()

    deleted = prune_ping_results()
    assert deleted == 0
