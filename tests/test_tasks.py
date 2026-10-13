"""
Automated Test Suite for Worker Tasks and Network Probing Integration.
"""

from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from app.db import get_sync_db
from app.enums import MonitorStatus, PingOutcome
from app.models import Monitor, PingResult
from app.net import PingResultDTO
from app.tasks import execute_ping
from app.worker import celery_app


def _create_test_monitor(
    name: str = "Test Target",
    url: str = "https://example.com",
) -> int:
    """Helper to synchronously seed a Monitor into PostgreSQL."""
    with get_sync_db() as session:
        monitor = Monitor(
            name=name,
            url=url,
            check_interval_seconds=60,
            status=MonitorStatus.PENDING.value,
            next_check_at=datetime.now(UTC),
        )
        session.add(monitor)
        session.flush()
        session.refresh(monitor)
        return monitor.id


@patch("app.tasks.robust_ping")
def test_execute_ping_success(mock_ping: MagicMock) -> None:
    """
    Verify execute_ping performs probe via robust_ping,
    records PingResult with check_type='monitor',
    updates monitor status to 'up', and records last_checked_at.
    """
    mock_ping.return_value = PingResultDTO(
        outcome=PingOutcome.UP,
        status_code=200,
        latency_ms=25.5,
        error_detail=None,
        original_url="https://healthy-target.com",
        final_url="https://healthy-target.com",
    )

    mid = _create_test_monitor(url="https://healthy-target.com")

    result = execute_ping(mid)
    assert result["status"] == "completed"
    assert result["monitor_id"] == mid
    assert result["status_code"] == 200
    assert result["error"] is None
    assert result["latency_ms"] > 0

    # Verify DB state
    with get_sync_db() as session:
        mon = session.get(Monitor, mid)
        assert mon is not None
        assert mon.status == MonitorStatus.UP.value
        assert mon.last_checked_at is not None

        pr = session.query(PingResult).filter_by(monitor_id=mid).first()
        assert pr is not None
        assert pr.status_code == 200
        assert pr.error is None


@patch("app.tasks.robust_ping")
def test_execute_ping_status_mappings(mock_ping: MagicMock) -> None:
    """Verify HTTP 404 maps to DEGRADED and HTTP 500 maps to DOWN."""
    mid = _create_test_monitor(url="https://status-target.com")

    # 404 -> DEGRADED
    mock_ping.return_value = PingResultDTO(
        outcome=PingOutcome.DEGRADED,
        status_code=404,
        latency_ms=18.0,
        error_detail=None,
        original_url="https://status-target.com",
        final_url="https://status-target.com",
    )
    execute_ping(mid)
    with get_sync_db() as session:
        assert session.get(Monitor, mid).status == MonitorStatus.DEGRADED.value

    # 500 -> DOWN
    mock_ping.return_value = PingResultDTO(
        outcome=PingOutcome.DOWN,
        status_code=500,
        latency_ms=22.0,
        error_detail=None,
        original_url="https://status-target.com",
        final_url="https://status-target.com",
    )
    execute_ping(mid)
    with get_sync_db() as session:
        assert session.get(Monitor, mid).status == MonitorStatus.DOWN.value


def test_execute_ping_nonexistent_monitor() -> None:
    """Verify execute_ping handles non-existent monitor cleanly without raising exception."""
    result = execute_ping(99999)
    assert result["status"] == "not_found"
    assert result["monitor_id"] == 99999


@patch("app.tasks.robust_ping")
def test_execute_ping_timeout_permanent_failure(mock_ping: MagicMock) -> None:
    """Verify exhausted retries persist error='read_timeout' and set Monitor.status='down'."""
    mock_ping.return_value = PingResultDTO(
        outcome=PingOutcome.UNREACHABLE,
        status_code=None,
        latency_ms=5000.0,
        error_detail="read_timeout",
        original_url="https://timeout-target.com",
        final_url=None,
    )

    mid = _create_test_monitor(url="https://timeout-target.com")

    # Set task.request.retries = 3 via Celery push_request
    execute_ping.push_request(retries=3)
    try:
        result = execute_ping(mid)
    finally:
        execute_ping.pop_request()

    assert result["status"] == "completed"
    assert "timeout" in result["error"]
    assert result["status_code"] is None

    with get_sync_db() as session:
        mon = session.get(Monitor, mid)
        assert mon.status == MonitorStatus.DOWN.value

        pr = session.query(PingResult).filter_by(monitor_id=mid).first()
        assert pr is not None
        assert "timeout" in pr.error


@patch("app.tasks.robust_ping")
def test_task_idempotency_multiple_executions(mock_ping: MagicMock) -> None:
    """
    Verify that running tasks repeatedly does not corrupt monitor state,
    properly records successive telemetry in PingResult, and updates last_checked_at.
    """
    mock_ping.return_value = PingResultDTO(
        outcome=PingOutcome.UP,
        status_code=200,
        latency_ms=15.0,
        error_detail=None,
        original_url="https://idempotent-target.com",
        final_url="https://idempotent-target.com",
    )

    mid = _create_test_monitor(
        url="https://idempotent-target.com",
    )

    # Run 2 pings
    execute_ping(mid)
    execute_ping(mid)

    with get_sync_db() as session:
        mon = session.get(Monitor, mid)
        assert mon.status == MonitorStatus.UP.value

        results = session.query(PingResult).filter_by(monitor_id=mid).all()
        assert len(results) == 2


@patch("app.tasks.robust_ping")
def test_celery_delay_eager_execution(mock_ping: MagicMock) -> None:
    """
    Verify tasks can be queued via Celery's .delay() method.
    Uses Celery eager mode to test queueing mechanics within the test process.
    """
    mock_ping.return_value = PingResultDTO(
        outcome=PingOutcome.UP,
        status_code=200,
        latency_ms=20.0,
        error_detail=None,
        original_url="https://celery-eager.com",
        final_url="https://celery-eager.com",
    )

    mid = _create_test_monitor(
        url="https://celery-eager.com",
    )

    celery_app.conf.task_always_eager = True
    try:
        async_ping = execute_ping.delay(mid)
        assert async_ping.ready()
        ping_res = async_ping.get()
        assert ping_res["status"] == "completed"
    finally:
        celery_app.conf.task_always_eager = False


@patch("app.tasks.robust_ping")
def test_execute_ping_soft_time_limit_exceeded(mock_ping: MagicMock) -> None:
    """
    Verify SoftTimeLimitExceeded writes PingResult(outcome=DOWN, error='task_soft_time_limit')
    and updates status='down'.
    """
    from celery.exceptions import SoftTimeLimitExceeded

    mock_ping.side_effect = SoftTimeLimitExceeded("Task soft time limit exceeded")
    mid = _create_test_monitor(url="https://soft-limit-ping.com")

    result = execute_ping(mid)
    assert result["status"] == "completed"
    assert result["outcome"] == PingOutcome.DOWN.value
    assert result["error"] == "task_soft_time_limit"

    with get_sync_db() as session:
        mon = session.get(Monitor, mid)
        assert mon.status == MonitorStatus.DOWN.value
        assert mon.last_checked_at is not None

        pr = session.query(PingResult).filter_by(monitor_id=mid).first()
        assert pr is not None
        assert pr.error == "task_soft_time_limit"
