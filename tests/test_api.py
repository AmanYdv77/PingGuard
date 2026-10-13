"""
Comprehensive test suite for PingGuard REST API & Persistence Layer.
Converted to idiomatic pytest functions with standard fixtures.
"""

import ast
import logging
import os
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from app.main import app
from app.models import Monitor, PingResult
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from tests.conftest import TEST_API_KEY


# =========================================================================
# Health & Discovery
# =========================================================================
def test_health_check(client: TestClient) -> None:
    """Verify the basic service health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "PingGuard API"


def test_health_endpoint(client: TestClient) -> None:
    """Verify GET /health returns 200 OK with status ok or healthy and version."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") in ["ok", "healthy"]
    assert data.get("service") == "PingGuard API"
    assert data.get("version") == "1.0.0"


def test_swagger_ui(client: TestClient) -> None:
    """Verify Swagger UI (/docs) returns HTTP 200 with interactive HTML."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.text.lower()


def test_version_consistency() -> None:
    """Verify app.__version__ matches the version declared in pyproject.toml."""
    import app as app_module

    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    declared_version = data.get("project", {}).get("version") or data.get("tool", {}).get(
        "poetry", {}
    ).get("version")
    assert app_module.__version__ == declared_version
    assert app_module.__version__ == "1.0.0"


# =========================================================================
# Monitor Creation & Defaults
# =========================================================================
def test_create_monitor_valid_and_backward_compatible(auth_client: TestClient) -> None:
    """
    Standard monitor creation request format works with exact defaults.
    Payload: {"name": "t", "url": "https://example.com"}
    Expected: 201 Created, check_interval_seconds=60, default status PENDING.
    """
    payload = {"name": "t", "url": "https://example.com"}
    response = auth_client.post("/monitors/", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert data["id"] == 1
    assert data["name"] == "t"
    assert data["url"] == "https://example.com/"
    assert data["check_interval_seconds"] == 60  # Default
    assert data["status"] == "pending"
    assert data["last_checked_at"] is None
    assert data["next_check_at"] is not None

    # Verify keep-alive fields are NOT present
    assert "mode" not in data
    assert "keep_alive_enabled" not in data
    assert "keep_alive_interval_seconds" not in data
    assert "keep_alive_path" not in data


def test_create_monitor_custom_interval(auth_client: TestClient) -> None:
    """Verify custom check_interval_seconds within valid range."""
    payload = {
        "name": "Production API",
        "url": "https://api.example.org/health",
        "check_interval_seconds": 30,
    }
    response = auth_client.post("/monitors/", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["check_interval_seconds"] == 30


def test_get_returns_all_monitor_fields(auth_client: TestClient) -> None:
    """GET /monitors/{id} returns all expected monitor fields without keep-alive fields."""
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Inspectable Monitor",
            "url": "https://example.com",
            "check_interval_seconds": 120,
        },
    )
    created_id = create_resp.json()["id"]

    get_resp = auth_client.get(f"/monitors/{created_id}")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert data["name"] == "Inspectable Monitor"
    assert data["url"] == "https://example.com/"
    assert data["check_interval_seconds"] == 120
    assert "mode" not in data
    assert "keep_alive_enabled" not in data
    assert "keep_alive_interval_seconds" not in data
    assert "keep_alive_path" not in data


def test_update_monitor_configuration(auth_client: TestClient) -> None:
    """PATCH /monitors/{id} updates monitor configuration."""
    # 1. Create standard monitor
    create_resp = auth_client.post(
        "/monitors/", json={"name": "Updatable", "url": "https://example.com"}
    )
    mid = create_resp.json()["id"]

    # 2. Update name and interval
    patch_resp = auth_client.patch(
        f"/monitors/{mid}",
        json={
            "name": "Updated Name",
            "check_interval_seconds": 180,
        },
    )
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert data["name"] == "Updated Name"
    assert data["check_interval_seconds"] == 180
    assert "mode" not in data


def test_get_unknown_monitor_returns_404(auth_client: TestClient) -> None:
    """GET /monitors/99999 returns HTTP 404 'Monitor not found'."""
    response = auth_client.get("/monitors/99999")
    assert response.status_code == 404
    assert response.json() == {"detail": "Monitor not found"}


def test_invalid_original_fields_produce_422(auth_client: TestClient) -> None:
    """Invalid URL, empty name, name too long, interval bounds still return 422."""
    assert auth_client.post("/monitors/", json={"name": "A", "url": "not-url"}).status_code == 422
    assert (
        auth_client.post("/monitors/", json={"name": "", "url": "https://example.com"}).status_code
        == 422
    )
    assert (
        auth_client.post(
            "/monitors/", json={"name": "A" * 121, "url": "https://example.com"}
        ).status_code
        == 422
    )
    assert (
        auth_client.post(
            "/monitors/",
            json={"name": "A", "url": "https://example.com", "check_interval_seconds": 10},
        ).status_code
        == 422
    )
    assert (
        auth_client.post(
            "/monitors/",
            json={"name": "A", "url": "https://example.com", "check_interval_seconds": 90000},
        ).status_code
        == 422
    )


# =========================================================================
# Architectural Test: Network Isolation During Monitor Registration
# =========================================================================
def test_creating_monitor_never_probes_network(auth_client: TestClient) -> None:
    """
    CRITICAL ARCHITECTURAL BOUNDARY:
    Verify that registering a monitor (with or without keep-alive) makes ZERO
    outbound HTTP requests to the target destination.
    Patches app.net.perform_http_probe and httpx.AsyncClient.send with sentinels
    that raise AssertionError if called; asserts creation succeeds and neither sentinel fired.
    """

    def probe_sentinel(*args, **kwargs):
        raise AssertionError(
            "app.net.perform_http_probe was unexpectedly called during monitor creation"
        )

    def httpx_sentinel(*args, **kwargs):
        raise AssertionError(
            "httpx.AsyncClient.send was unexpectedly called during monitor creation"
        )

    with (
        patch("app.net.perform_http_probe", side_effect=probe_sentinel),
        patch("httpx.AsyncClient.send", side_effect=httpx_sentinel),
    ):
        response = auth_client.post(
            "/monitors/",
            json={
                "name": "Air-Gapped Isolation Test",
                "url": "https://example.com",
            },
        )
        assert response.status_code == 201


def test_list_monitors_returns_monitors(auth_client: TestClient) -> None:
    """Verify list endpoint returns created monitors without keep-alive fields."""
    auth_client.post("/monitors/", json={"name": "M1", "url": "https://m1.com"})
    auth_client.post("/monitors/", json={"name": "M2", "url": "https://m2.com"})
    response = auth_client.get("/monitors/")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2
    for m in data:
        assert "mode" not in m
        assert "keep_alive_enabled" not in m


def test_openapi_schema_does_not_expose_removed_models(client: TestClient) -> None:
    """Verify /openapi.json does not expose removed keep-alive models or fields."""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()

    schemas = schema.get("components", {}).get("schemas", {})
    assert "MonitorMode" not in schemas

    create_props = schemas["MonitorCreate"]["properties"]
    assert "mode" not in create_props
    assert "keep_alive_enabled" not in create_props
    assert "keep_alive_interval_seconds" not in create_props
    assert "keep_alive_path" not in create_props


def test_update_monitor_put(auth_client: TestClient) -> None:
    """Verify PUT endpoint works symmetrically with monitor configurations."""
    create_resp = auth_client.post(
        "/monitors/", json={"name": "Initial", "url": "https://example.com"}
    )
    mid = create_resp.json()["id"]

    put_resp = auth_client.put(
        f"/monitors/{mid}",
        json={
            "name": "PUT Updated",
            "url": "https://example.com/updated",
            "check_interval_seconds": 120,
        },
    )
    assert put_resp.status_code == 200
    data = put_resp.json()
    assert data["name"] == "PUT Updated"
    assert data["check_interval_seconds"] == 120
    assert "mode" not in data


def test_list_monitors_pagination(auth_client: TestClient) -> None:
    """Verify pagination with skip and limit parameters."""
    for i in range(1, 6):
        auth_client.post("/monitors/", json={"name": f"M{i}", "url": f"https://m{i}.com"})
    resp = auth_client.get("/monitors/?skip=1&limit=2")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    assert data[0]["name"] == "M2"
    assert data[1]["name"] == "M3"


# =========================================================================
# Persistence, Restart & ORM Relationships
# =========================================================================
def test_monitor_fields_persisted_in_postgresql(auth_client: TestClient, db_session) -> None:
    """
    Verify Monitor configuration is persisted
    durably in PostgreSQL with exact column values and next_check_at timestamp.
    """
    payload = {
        "name": "XYZ Website",
        "url": "https://xyz.com",
        "check_interval_seconds": 60,
    }
    create_resp = auth_client.post("/monitors/", json=payload)
    assert create_resp.status_code == 201
    created_id = create_resp.json()["id"]

    mon = db_session.get(Monitor, created_id)
    assert mon is not None
    assert mon.name == "XYZ Website"
    assert mon.url == "https://xyz.com/"
    assert mon.check_interval_seconds == 60
    assert mon.next_check_at is not None


def test_persistence_across_app_restart(auth_client: TestClient) -> None:
    """
    Verify monitor data survives
    a complete FastAPI application teardown and restart.
    """
    # 1. Create monitor in session 1
    payload = {
        "name": "Durable Monitor",
        "url": "https://durable.example.com",
        "check_interval_seconds": 90,
    }
    res1 = auth_client.post("/monitors/", json=payload)
    assert res1.status_code == 201
    mid = res1.json()["id"]

    # 2. Simulate FastAPI shutdown and restart
    for mod in list(sys.modules.keys()):
        if mod.startswith("app.main"):
            del sys.modules[mod]

    from app.main import app as restarted_app

    restarted_client = TestClient(restarted_app, headers={"X-API-Key": TEST_API_KEY})

    # 3. Retrieve from new application instance
    res2 = restarted_client.get(f"/monitors/{mid}")
    assert res2.status_code == 200
    data = res2.json()

    assert data["id"] == mid
    assert data["name"] == "Durable Monitor"
    assert data["url"] == "https://durable.example.com/"
    assert data["check_interval_seconds"] == 90
    assert "mode" not in data


def test_ping_result_orm_relationship(db_session) -> None:
    """
    Verify PingResult ORM model and relationship to Monitor.
    """
    monitor = Monitor(
        name="Relationship Test Monitor",
        url="https://rel.example.com",
        check_interval_seconds=60,
    )
    db_session.add(monitor)
    db_session.flush()
    mid = monitor.id

    now = datetime.now(UTC)
    pr1 = PingResult(
        monitor_id=mid,
        status_code=200,
        latency_ms=120.0,
        error=None,
        checked_at=now,
    )
    pr2 = PingResult(
        monitor_id=mid,
        status_code=200,
        latency_ms=85.5,
        error=None,
        checked_at=now,
    )
    db_session.add_all([pr1, pr2])
    db_session.commit()

    results = (
        db_session.query(PingResult)
        .filter(PingResult.monitor_id == mid)
        .order_by(PingResult.id.asc())
        .all()
    )
    assert len(results) == 2
    assert results[0].latency_ms == 120.0
    assert results[1].latency_ms == 85.5


def test_cascade_delete_monitor_and_ping_results(db_session) -> None:
    """
    Verify cascade delete:
    Deleting a Monitor must cascade delete all associated PingResult rows.
    """
    monitor = Monitor(
        name="Cascade Target",
        url="https://cascade.example.com",
        check_interval_seconds=60,
    )
    db_session.add(monitor)
    db_session.flush()
    mid = monitor.id

    pr = PingResult(
        monitor_id=mid,
        status_code=200,
        latency_ms=99.0,
        checked_at=datetime.now(UTC),
    )
    db_session.add(pr)
    db_session.commit()

    assert db_session.query(PingResult).filter(PingResult.monitor_id == mid).count() == 1

    db_session.delete(monitor)
    db_session.commit()

    assert db_session.query(PingResult).filter(PingResult.monitor_id == mid).count() == 0


def test_delete_monitor_api(auth_client: TestClient) -> None:
    """Verify DELETE /monitors/{id} deletes the monitor and returns 204."""
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Delete Me Test",
            "url": "https://example.com/delete-test",
            "check_interval_seconds": 60,
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    del_resp = auth_client.delete(f"/monitors/{mid}")
    assert del_resp.status_code == 204

    get_resp = auth_client.get(f"/monitors/{mid}")
    assert get_resp.status_code == 404


def test_get_monitor_results_api(auth_client: TestClient) -> None:
    """Verify GET /monitors/{id}/results returns historical telemetry."""
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Results Test",
            "url": "https://example.com/results-test",
            "check_interval_seconds": 60,
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    # Query empty results
    res_resp = auth_client.get(f"/monitors/{mid}/results")
    assert res_resp.status_code == 200
    assert res_resp.json() == []

    # Non-existent monitor 404
    bad_resp = auth_client.get("/monitors/999999/results")
    assert bad_resp.status_code == 404


def test_check_unreachable_status_does_not_break_list_monitors(auth_client: TestClient) -> None:
    """
    REGRESSION TEST:
    1. Create monitor with unreachable/dead URL.
    2. Call POST /monitors/{id}/check which returns 202 and queues Celery task.
    3. Run worker task.
    4. Verify GET /monitors/ and GET /monitors/{id} return 200 OK and valid status (not 500).
    """
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Dead Host Monitor",
            "url": "https://nonexistent-fake-target-domain-999.xyz",
            "check_interval_seconds": 60,
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    # 2. Trigger on-demand check (returns 202 Accepted, queues Celery task)
    from app.tasks import execute_ping

    with patch("app.main.execute_ping.delay") as mock_delay:
        check_resp = auth_client.post(f"/monitors/{mid}/check")
        assert check_resp.status_code == 202
        mock_delay.assert_called_once_with(mid)

    # Run the queued worker task
    execute_ping(mid)

    # 3. GET /monitors/{id} and GET /monitors/ must return 200 OK with valid MonitorStatus
    get_one = auth_client.get(f"/monitors/{mid}")
    assert get_one.status_code == 200
    assert get_one.json()["status"] == "down"

    get_all = auth_client.get("/monitors/")
    assert get_all.status_code == 200
    statuses = [m["status"] for m in get_all.json() if m["id"] == mid]
    assert statuses == ["down"]


def test_unreachable_status_db_constraint_rejected(db_session) -> None:
    """
    Verify inserting status='unreachable' directly into monitors table violates DB CHECK constraint.
    """
    monitor = Monitor(
        name="Invalid Status Target",
        url="https://invalid-status.example.com",
        check_interval_seconds=60,
        status="unreachable",
    )
    db_session.add(monitor)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()


# =========================================================================
# Asynchronous /check Endpoint & Architectural Boundaries
# =========================================================================
def test_test_url_endpoint_removed_returns_404(client: TestClient) -> None:
    """Verify the unauthenticated /test-url diagnostic endpoint is completely deleted (404)."""
    response = client.post("/test-url", json={"url": "https://example.com"})
    assert response.status_code == 404


def test_check_monitor_queues_celery_task_returns_202(auth_client: TestClient) -> None:
    """Verify POST /monitors/{id}/check returns 202 Accepted and queues execute_ping.delay(id)."""
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Async Check Target",
            "url": "https://example.com",
            "check_interval_seconds": 60,
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    with patch("app.main.execute_ping.delay") as mock_delay:
        resp = auth_client.post(f"/monitors/{mid}/check")
        assert resp.status_code == 202
        assert resp.json() == {"status": "queued", "monitor_id": mid}
        mock_delay.assert_called_once_with(mid)


def test_check_monitor_unknown_id_returns_404(auth_client: TestClient) -> None:
    """Verify POST /monitors/{id}/check returns 404 when monitor ID does not exist."""
    resp = auth_client.post("/monitors/999999/check")
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Monitor not found"


def test_api_architecture_contains_no_outbound_probing() -> None:
    """
    Architectural test: parses app/main.py with AST and asserts it contains
    zero references to app.net, robust_ping, run_in_executor, or httpx.
    """
    main_path = Path(__file__).resolve().parent.parent / "app" / "main.py"
    with open(main_path, encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename="main.py")

    disallowed_names = {"robust_ping", "run_in_executor", "httpx"}
    violations = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (
                    alias.name == "app.net"
                    or alias.name.startswith("app.net.")
                    or alias.name == "httpx"
                ):
                    violations.append(f"Import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "app.net" or (node.module and node.module.startswith("app.net")):
                violations.append(f"from {node.module} import ...")
            for alias in node.names:
                if alias.name in disallowed_names:
                    violations.append(f"Imported name {alias.name}")
        elif isinstance(node, ast.Name) and node.id in disallowed_names:
            violations.append(f"Name reference {node.id}")
        elif isinstance(node, ast.Attribute) and node.attr in disallowed_names:
            violations.append(f"Attribute access {node.attr}")

    assert violations == [], (
        f"app/main.py must not reference outbound probing or run_in_executor. Found: {violations}"
    )


# =========================================================================
# API Key Authentication Tests
# =========================================================================
def test_unauthenticated_request_rejected(client: TestClient) -> None:
    """Missing X-API-Key header returns HTTP 401 with WWW-Authenticate header."""
    resp = client.get("/monitors/")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid or missing API key"}
    assert resp.headers.get("www-authenticate") == "ApiKey"


def test_invalid_api_key_rejected(client: TestClient) -> None:
    """Wrong X-API-Key header returns HTTP 401 with WWW-Authenticate header."""
    resp = client.get("/monitors/", headers={"X-API-Key": "wrong-key-value-1234567890"})
    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid or missing API key"}
    assert resp.headers.get("www-authenticate") == "ApiKey"


def test_health_check_remains_unauthenticated(client: TestClient) -> None:
    """GET /health remains public and succeeds without X-API-Key."""
    resp = client.get("/health")
    assert resp.status_code == 200


def test_valid_api_key_accepted(client: TestClient) -> None:
    """Valid X-API-Key header grants access to /monitors/ endpoints."""
    resp = client.get("/monitors/", headers={"X-API-Key": TEST_API_KEY})
    assert resp.status_code == 200


def test_openapi_declares_security_scheme() -> None:
    """Verify the OpenAPI schema declares APIKeyHeader security scheme."""
    openapi_schema = app.openapi()
    components = openapi_schema.get("components", {})
    security_schemes = components.get("securitySchemes", {})
    assert "APIKeyHeader" in security_schemes
    assert security_schemes["APIKeyHeader"]["type"] == "apiKey"
    assert security_schemes["APIKeyHeader"]["name"] == "X-API-Key"
    assert security_schemes["APIKeyHeader"]["in"] == "header"


# =========================================================================
# CORS Configuration Tests
# =========================================================================
def test_cors_architecture_contains_no_wildcard() -> None:
    """Verify app/main.py does not contain wildcard allow_origins."""
    main_py = (Path(__file__).resolve().parent.parent / "app" / "main.py").read_text(
        encoding="utf-8"
    )
    assert 'allow_origins=["*"]' not in main_py
    assert "allow_origins=['*']" not in main_py


def test_cors_disallowed_origin_no_headers(client: TestClient) -> None:
    """A disallowed origin receives no CORS headers."""
    resp = client.get("/health", headers={"Origin": "https://evil-unauthorized-site.com"})
    assert "access-control-allow-origin" not in resp.headers


def test_cors_allowed_origin_preflight_and_disallowed() -> None:
    """Preflight from allowed origin returns CORS headers; disallowed origin gets none."""
    import importlib

    from app.config import get_settings

    old_origins = os.environ.get("CORS_ALLOWED_ORIGINS")
    os.environ["CORS_ALLOWED_ORIGINS"] = "http://localhost:3000"
    get_settings.cache_clear()
    import app.main

    importlib.reload(app.main)

    try:
        cors_client = TestClient(app.main.app)

        # Allowed origin preflight
        preflight = cors_client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, X-API-Key",
            },
        )
        assert preflight.status_code == 200
        assert preflight.headers.get("access-control-allow-origin") == "http://localhost:3000"
        assert "POST" in preflight.headers.get("access-control-allow-methods", "")
        assert "X-API-Key" in preflight.headers.get("access-control-allow-headers", "")
        assert preflight.headers.get("access-control-max-age") == "600"
        assert "access-control-allow-credentials" not in preflight.headers

        # Disallowed origin
        disallowed = cors_client.options(
            "/health",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "POST",
            },
        )
        assert "access-control-allow-origin" not in disallowed.headers
    finally:
        if old_origins is not None:
            os.environ["CORS_ALLOWED_ORIGINS"] = old_origins
        else:
            os.environ.pop("CORS_ALLOWED_ORIGINS", None)
        get_settings.cache_clear()
        importlib.reload(app.main)


# =========================================================================
# Rate Limiting & Monitor Cap Tests
# =========================================================================
def test_write_rate_limit_allowed_under_limit(auth_client: TestClient) -> None:
    """Write requests within the limit succeed."""
    import app.main
    from app.ratelimit import InMemoryRateLimiter, get_rate_limiter

    limiter = InMemoryRateLimiter()
    app.main.app.dependency_overrides[get_rate_limiter] = lambda: limiter

    for i in range(3):
        resp = auth_client.post("/monitors/", json={"name": f"M{i}", "url": f"https://m{i}.com"})
        assert resp.status_code == 201


def test_write_rate_limit_429_over_limit(auth_client: TestClient) -> None:
    """Exceeding write rate limit returns HTTP 429 with Retry-After header."""
    import app.main
    from app.ratelimit import InMemoryRateLimiter, get_rate_limiter

    limiter = InMemoryRateLimiter()
    app.main.app.dependency_overrides[get_rate_limiter] = lambda: limiter

    from app.config import get_settings

    settings = get_settings()
    limit = settings.rate_limit_writes_per_minute

    # Simulate exhausting the limit
    for i in range(limit):
        resp = auth_client.post("/monitors/", json={"name": f"M{i}", "url": f"https://m{i}.com"})
        assert resp.status_code == 201

    # The limit + 1 request must fail with 429
    blocked = auth_client.post("/monitors/", json={"name": "Over", "url": "https://over.com"})
    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "rate limit exceeded"}
    assert "retry-after" in blocked.headers
    retry_after = int(blocked.headers["retry-after"])
    assert retry_after > 0


def test_write_rate_limit_window_reset(auth_client: TestClient) -> None:
    """Injectable clock advancing beyond window_seconds resets the limit without sleeps."""
    import app.main
    from app.ratelimit import InMemoryRateLimiter, get_rate_limiter

    current_time = [1000.0]
    limiter = InMemoryRateLimiter(clock=lambda: current_time[0])
    app.main.app.dependency_overrides[get_rate_limiter] = lambda: limiter

    from app.config import get_settings

    limit = get_settings().rate_limit_writes_per_minute

    for i in range(limit):
        resp = auth_client.post("/monitors/", json={"name": f"M{i}", "url": f"https://m{i}.com"})
        assert resp.status_code == 201

    # Blocked at limit
    resp = auth_client.post("/monitors/", json={"name": "Blocked", "url": "https://blocked.com"})
    assert resp.status_code == 429

    # Advance clock by 61 seconds
    current_time[0] += 61.0

    # Now allowed again
    resp2 = auth_client.post(
        "/monitors/", json={"name": "AllowedAfterReset", "url": "https://reset.com"}
    )
    assert resp2.status_code == 201


def test_write_rate_limit_redis_failure_fails_open(
    auth_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    """When Redis encounters an error, rate limiter fails open with logged warning."""
    import app.main
    import redis.exceptions
    from app.ratelimit import get_rate_limiter
    from app.ratelimit import logger as rl_logger

    class FailingRedisLimiter:
        async def hit(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
            raise redis.exceptions.ConnectionError("Redis connection lost")

    app.main.app.dependency_overrides[get_rate_limiter] = lambda: FailingRedisLimiter()
    rl_logger.disabled = False

    with caplog.at_level(logging.WARNING, logger="app.ratelimit"):
        resp = auth_client.post(
            "/monitors/", json={"name": "FailOpen", "url": "https://failopen.com"}
        )
        assert resp.status_code == 201

    assert any(
        "fail open" in record.message.lower() or "redis" in record.message.lower()
        for record in caplog.records
    )


def test_get_endpoints_not_rate_limited(auth_client: TestClient) -> None:
    """GET endpoints are not subject to write rate limits."""
    import app.main
    from app.ratelimit import InMemoryRateLimiter, get_rate_limiter

    limiter = InMemoryRateLimiter()
    app.main.app.dependency_overrides[get_rate_limiter] = lambda: limiter

    # Create one monitor
    resp = auth_client.post("/monitors/", json={"name": "M1", "url": "https://m1.com"})
    assert resp.status_code == 201
    mid = resp.json()["id"]

    from app.config import get_settings

    limit = get_settings().rate_limit_writes_per_minute

    # Exhaust write limit
    for i in range(limit - 1):
        auth_client.post("/monitors/", json={"name": f"M{i}", "url": f"https://m{i}.com"})

    # Write is now blocked
    write_resp = auth_client.post(
        "/monitors/", json={"name": "Exceeded", "url": "https://exceeded.com"}
    )
    assert write_resp.status_code == 429

    # GET /monitors/ and GET /monitors/{id} must still return 200
    get_list_resp = auth_client.get("/monitors/")
    assert get_list_resp.status_code == 200

    get_one_resp = auth_client.get(f"/monitors/{mid}")
    assert get_one_resp.status_code == 200


def test_monitor_cap_enforced(auth_client: TestClient) -> None:
    """Creating monitors beyond max_monitors returns HTTP 409 with 'monitor limit reached'."""
    import app.main
    from app.config import get_settings
    from app.ratelimit import InMemoryRateLimiter, get_rate_limiter

    limiter = InMemoryRateLimiter()
    app.main.app.dependency_overrides[get_rate_limiter] = lambda: limiter

    old_cap = os.environ.get("MAX_MONITORS")
    os.environ["MAX_MONITORS"] = "2"
    get_settings.cache_clear()

    try:
        # 1st monitor -> OK
        r1 = auth_client.post("/monitors/", json={"name": "M1", "url": "https://m1.com"})
        assert r1.status_code == 201

        # 2nd monitor -> OK (count is now 2)
        r2 = auth_client.post("/monitors/", json={"name": "M2", "url": "https://m2.com"})
        assert r2.status_code == 201

        # 3rd monitor -> 409 Conflict
        r3 = auth_client.post("/monitors/", json={"name": "M3", "url": "https://m3.com"})
        assert r3.status_code == 409
        assert r3.json() == {"detail": "monitor limit reached"}
    finally:
        if old_cap is not None:
            os.environ["MAX_MONITORS"] = old_cap
        else:
            os.environ.pop("MAX_MONITORS", None)
        get_settings.cache_clear()


# =========================================================================
# Additional Behaviour Tests for Untested Paths
# =========================================================================
def test_create_monitor_validation_errors(auth_client: TestClient) -> None:
    """
    Verify POST /monitors returns HTTP 422 for invalid schemes
    and out-of-range intervals.
    """
    # Invalid schemes
    assert (
        auth_client.post("/monitors/", json={"name": "FTP", "url": "ftp://example.com"}).status_code
        == 422
    )
    assert (
        auth_client.post(
            "/monitors/", json={"name": "File", "url": "file:///etc/passwd"}
        ).status_code
        == 422
    )
    assert (
        auth_client.post(
            "/monitors/", json={"name": "Gopher", "url": "gopher://example.com"}
        ).status_code
        == 422
    )

    # Check interval boundary violations
    assert (
        auth_client.post(
            "/monitors/",
            json={"name": "Low", "url": "https://example.com", "check_interval_seconds": 14},
        ).status_code
        == 422
    )
    assert (
        auth_client.post(
            "/monitors/",
            json={"name": "High", "url": "https://example.com", "check_interval_seconds": 86401},
        ).status_code
        == 422
    )


def test_patch_monitor_partial_updates(auth_client: TestClient) -> None:
    """Verify PATCH /monitors/{id} updates only specified fields and leaves others untouched."""
    # Create initial monitor
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Initial Name",
            "url": "https://patch-test.com",
            "check_interval_seconds": 60,
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    # 1. Update name only
    r_name = auth_client.patch(f"/monitors/{mid}", json={"name": "Updated Name"})
    assert r_name.status_code == 200
    assert r_name.json()["name"] == "Updated Name"
    assert r_name.json()["check_interval_seconds"] == 60
    assert r_name.json()["url"] == "https://patch-test.com/"

    # 2. Update check_interval_seconds only
    r_int = auth_client.patch(f"/monitors/{mid}", json={"check_interval_seconds": 120})
    assert r_int.status_code == 200
    assert r_int.json()["name"] == "Updated Name"
    assert r_int.json()["check_interval_seconds"] == 120

    # 3. Patch non-existent monitor -> 404
    r_404 = auth_client.patch("/monitors/999999", json={"name": "Ghost"})
    assert r_404.status_code == 404
    assert r_404.json() == {"detail": "Monitor not found"}


def test_delete_monitor_cascade_deletes_ping_results_api(
    auth_client: TestClient, db_session
) -> None:
    """
    Verify API DELETE /monitors/{id} deletes the monitor
    and cascades to delete all attached ping_results.
    """
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Cascade API Monitor",
            "url": "https://cascade-api.com",
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    # Add 3 PingResult records for this monitor
    now = datetime.now(UTC)
    for i in range(3):
        db_session.add(
            PingResult(
                monitor_id=mid,
                status_code=200,
                latency_ms=25.0 + i,
                checked_at=now,
            )
        )
    db_session.commit()

    # Verify rows exist
    assert db_session.query(PingResult).filter_by(monitor_id=mid).count() == 3

    # Delete the monitor via REST API
    del_resp = auth_client.delete(f"/monitors/{mid}")
    assert del_resp.status_code == 204

    # Verify both Monitor and its PingResults are gone
    assert db_session.get(Monitor, mid) is None
    assert db_session.query(PingResult).filter_by(monitor_id=mid).count() == 0


def test_get_monitor_results_pagination_bounds(auth_client: TestClient, db_session) -> None:
    """
    Verify GET /monitors/{id}/results validates pagination bounds
    (limit < 1 -> 422, limit > 500 -> 422).
    """
    create_resp = auth_client.post(
        "/monitors/",
        json={
            "name": "Pagination Bounds Monitor",
            "url": "https://bounds.com",
        },
    )
    assert create_resp.status_code == 201
    mid = create_resp.json()["id"]

    # Seed 10 PingResult entries
    now = datetime.now(UTC)
    for i in range(10):
        db_session.add(
            PingResult(
                monitor_id=mid,
                status_code=200,
                latency_ms=10.0 + i,
                checked_at=now,
            )
        )
    db_session.commit()

    # limit=0 -> 422 (must be >= 1)
    r_zero = auth_client.get(f"/monitors/{mid}/results?limit=0")
    assert r_zero.status_code == 422

    # limit=-5 -> 422
    r_neg = auth_client.get(f"/monitors/{mid}/results?limit=-5")
    assert r_neg.status_code == 422

    # limit=501 -> 422 (must be <= 500)
    r_excess = auth_client.get(f"/monitors/{mid}/results?limit=501")
    assert r_excess.status_code == 422

    # Valid pagination: limit=5 returns 5 items
    r_valid = auth_client.get(f"/monitors/{mid}/results?limit=5")
    assert r_valid.status_code == 200
    assert len(r_valid.json()) == 5
