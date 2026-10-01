# PingGuard

[![CI](https://github.com/AmanYdv77/PingGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/AmanYdv77/PingGuard/actions/workflows/ci.yml)

PingGuard is a self-hosted, distributed HTTP uptime and health monitoring service built with FastAPI, PostgreSQL, Redis, and Celery.

---

## Features

- **Asynchronous Control Plane**: High-throughput REST API built on FastAPI and SQLAlchemy 2.0 Async for managing monitors and viewing execution telemetry.
- **Decoupled Distributed Probing**: Outbound HTTP checks are never executed in web requests; all probe workloads are queued to Celery workers backed by Redis.
- **SSRF & DNS Rebinding Protection**: Target hostnames are pre-resolved and checked against private/reserved IPv4 and IPv6 CIDR blocks; connections pin the resolved IP directly to mitigate time-of-check to time-of-use (TOCTOU) DNS rebinding attacks.
- **Configurable Probing Schedules**: Supports periodic health check intervals to monitor endpoint uptime, validate response codes, and record latency trends.
- **Rate Limiting & Capacity Guards**: Per-key write rate limiting prevents abuse, and a global monitor ceiling safeguards worker and database resources.
- **Automated Data Retention**: Scheduled Celery Beat maintenance job prunes historical probe results older than a configurable retention window (default 30 days) in bounded batches.
- **Operational Observability**: Distinct liveness (`/health`) and dependency-aware readiness (`/ready`) endpoints, correlated `X-Request-ID` tracing, and structured JSON logging.

---

## Architecture

```mermaid
flowchart TD
    subgraph Clients
        User[Client / Dashboard]
    end

    subgraph ControlPlane[API Service]
        FastAPI[FastAPI REST API]
    end

    subgraph DataPlane[Data Tier]
        Postgres[(PostgreSQL 15)]
        Redis[(Redis 7 Broker)]
    end

    subgraph WorkerFleet[Worker Fleet]
        Beat[Celery Beat Scheduler]
        Workers[Celery Worker Cluster]
    end

    subgraph Targets[External Networks]
        Websites[Target HTTP/HTTPS Services]
    end

    User -->|HTTP Requests + API Key| FastAPI
    FastAPI -->|Async Read/Write| Postgres
    FastAPI -->|Enqueue On-Demand Probes| Redis
    Beat -->|Periodic DB Sweep FOR UPDATE SKIP LOCKED| Postgres
    Beat -->|Dispatch Due Monitor Tasks| Redis
    Redis -->|Deliver Tasks| Workers
    Workers -->|SSRF-Validated Outbound Probe| Websites
    Workers -->|Sync Persist PingResult & Update Status| Postgres
```

PingGuard separates control plane API interactions from background network probing to maintain predictable request latencies. Clients interact exclusively with the FastAPI application, which validates input schemas, enforces rate limits, and persists configurations into PostgreSQL. The Celery Beat scheduler periodically sweeps PostgreSQL using row-level locking (`FOR UPDATE SKIP LOCKED`) to claim due monitors and publish execution jobs into Redis without creating duplicate tasks. Horizontally scalable Celery workers consume tasks from Redis, execute outbound HTTP probes through an SSRF-validated network engine, and commit latency and status results back to PostgreSQL. On-demand checks follow the same asynchronous pipeline: the API validates the target and enqueues a Celery task, immediately returning HTTP 202 Accepted.

---

## Quick Start (Docker)

Ensure Docker and Docker Compose are installed and running on your system.

### 1. Clone and Configure Environment

```bash
git clone https://github.com/AmanYdv77/PingGuard.git
cd PingGuard
cp .env.example .env
```

Generate secure secrets for PostgreSQL and the API authentication key:

```bash
# Generate database password and API key
python -c "import secrets; print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(24)); print('API_KEY=' + secrets.token_urlsafe(32))"
```

Paste these values into your `.env` file, ensuring `API_KEY` is at least 24 characters long.

### 2. Launch Services

```bash
docker compose up --build -d
```

Verify service containers are healthy:

```bash
docker compose ps
```

The interactive OpenAPI documentation is now available at [http://localhost:8000/docs](http://localhost:8000/docs).

### 3. Register a Monitor and Read Results

#### Linux / macOS (Bash)

```bash
# Set your API Key
API_KEY="your-generated-api-key"

# Register a new monitor
curl -X POST http://localhost:8000/monitors/ \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "name": "Example Domain",
    "url": "https://example.com",
    "check_interval_seconds": 60,
    "mode": "monitor"
  }'

# Trigger an immediate on-demand probe (returns HTTP 202)
curl -X POST http://localhost:8000/monitors/1/check \
  -H "X-API-Key: $API_KEY"

# Retrieve probe telemetry and execution history
curl -X GET http://localhost:8000/monitors/1/results \
  -H "X-API-Key: $API_KEY"
```

#### Windows (PowerShell)

```powershell
$headers = @{
    "Content-Type" = "application/json"
    "X-API-Key" = "your-generated-api-key"
}

# Register a new monitor
$body = @{
    name = "Example Domain"
    url = "https://example.com"
    check_interval_seconds = 60
    mode = "monitor"
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:8000/monitors/" -Method Post -Headers $headers -Body $body

# Trigger an immediate on-demand probe
Invoke-RestMethod -Uri "http://localhost:8000/monitors/1/check" -Method Post -Headers $headers

# Retrieve probe telemetry and execution history
Invoke-RestMethod -Uri "http://localhost:8000/monitors/1/results" -Method Get -Headers $headers
```

---

## Local Development

### 1. Prerequisites

- Python 3.12+
- Docker (for isolated PostgreSQL and Redis service containers)

### 2. Setup Virtual Environment

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements-dev.txt
```

### 3. Start Test Service Containers

Start dedicated test containers matching the test suite safety guards:

```bash
# Start test database (database name must end with _test)
docker run --name pingguard-test-db -e POSTGRES_PASSWORD=testpass -e POSTGRES_DB=pingguard_test -p 55432:5432 -d postgres:15-alpine

# Start test Redis broker
docker run --name pingguard-test-redis -p 6379:6379 -d redis:7-alpine
```

### 4. Execute Test Suite & Quality Checks

```bash
# Set mandatory test database URL
export TEST_DATABASE_URL="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"
# On Windows PowerShell: $env:TEST_DATABASE_URL="postgresql+asyncpg://postgres:testpass@localhost:55432/pingguard_test"

# Run tests with coverage
pytest --cov=app --cov-report=term-missing -q

# Run static analysis and formatting
ruff check .
ruff format --check .
mypy app
```

---

## Configuration Reference

Every application setting is typed and validated in `app/config.py` using Pydantic Settings:

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `ENVIRONMENT` | `dev` | Application runtime environment (`dev`, `test`, `prod`). Enforces strong credentials when not in test. |
| `API_KEY` | *Required* | Pre-shared API key for `/monitors/*` routes. Minimum length: 24 characters. |
| `CORS_ALLOWED_ORIGINS` | `[]` | Comma-separated list of allowed browser origins. Wildcards (`*`) are strictly rejected. |
| `DATABASE_URL` | *Required* | PostgreSQL connection string (`postgresql+asyncpg://...` or `postgresql://...`). |
| `REDIS_BROKER_URL` | `redis://localhost:6379/0` | Redis connection URL for Celery message broker. |
| `REDIS_RESULT_BACKEND_URL` | `redis://localhost:6379/1` | Redis connection URL for transient Celery task results. |
| `SWEEP_INTERVAL_SECONDS` | `15.0` | Frequency in seconds between Celery Beat database polling sweeps. |
| `CELERYBEAT_SCHEDULE_FILENAME`| `celerybeat-schedule` | Storage filename for Celery Beat persistent schedule timestamps. |
| `SWEEP_BATCH_SIZE` | `500` | Maximum number of due monitors claimed per database transaction. |
| `SWEEP_MAX_BATCHES` | `20` | Maximum consecutive batches claimed during a single scheduler cycle. |
| `HTTP_CONNECT_TIMEOUT` | `2.0` | Maximum seconds allowed to establish TCP/TLS connection during probes. |
| `HTTP_READ_TIMEOUT` | `5.0` | Maximum seconds allowed waiting for network response data per read. |
| `HTTP_WRITE_TIMEOUT` | `5.0` | Maximum seconds allowed to write outbound request bytes over socket. |
| `HTTP_POOL_TIMEOUT` | `2.0` | Maximum seconds allowed waiting for a pooled HTTP connection. |
| `HTTP_MAX_RESPONSE_BYTES` | `1048576` | Maximum response payload size read into memory (1 MB). Prevents memory exhaustion. |
| `HTTP_MAX_REDIRECTS` | `5` | Maximum number of HTTP redirect hops followed before halting. |
| `HTTP_USER_AGENT` | `PingGuard/1.0` | Outbound User-Agent header for standard uptime monitor probes. |
| `PROBE_TOTAL_TIMEOUT_SECONDS` | `8.0` | Hard deadline for entire probe execution across DNS, TLS, redirects, and streaming. |
| `CELERY_SOFT_TIME_LIMIT` | `10` | Worker soft execution limit in seconds. Must be `>= probe_total_timeout_seconds + 2`. |
| `CELERY_HARD_TIME_LIMIT` | `15` | Worker hard execution limit in seconds. Must be `>= celery_soft_time_limit + 3`. |
| `RATE_LIMIT_WRITES_PER_MINUTE` | `60` | Fixed-window write request limit per API key (or client IP fallback). |
| `MAX_MONITORS` | `100` | Global upper bound on registered monitors allowed in database. |
| `PING_RESULTS_RETENTION_DAYS` | `30` | Retention window in days. Older probe results are pruned daily. |
| `RETENTION_BATCH_SIZE` | `10000` | Maximum rows deleted per commit transaction in data retention task. |
| `LOG_LEVEL` | `INFO` | Logging threshold (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |
| `LOG_JSON` | `True` | Emits structured JSON logs containing timestamp, level, logger, message, and request ID. |

---

## API Overview

All `/monitors` endpoints require authentication via the `X-API-Key` HTTP header. Write operations are subject to rate limiting (`60 req/min`).

| Method | Path | Authentication | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | None (Public) | Service liveness probe. Returns HTTP 200 with service version. |
| `GET` | `/ready` | None (Public) | Service readiness probe. Returns HTTP 200 if PostgreSQL and Redis are reachable, else HTTP 503. |
| `POST` | `/monitors/` | `X-API-Key` | Register a new monitor endpoint. Subject to monitor capacity limit (`409 Conflict`). |
| `GET` | `/monitors/` | `X-API-Key` | List registered monitors with offset (`skip`) and pagination (`limit`). |
| `GET` | `/monitors/{id}` | `X-API-Key` | Retrieve monitor definition, current status, and scheduling metadata. |
| `PATCH`| `/monitors/{id}` | `X-API-Key` | Partially update monitor configuration, URLs, or check intervals. |
| `PUT` | `/monitors/{id}` | `X-API-Key` | Update monitor configuration. |
| `DELETE`| `/monitors/{id}` | `X-API-Key` | Delete monitor and automatically cascade delete all associated probe results. |
| `GET` | `/monitors/{id}/results` | `X-API-Key` | Retrieve historical probe results with optional `check_type` filtering. |
| `POST` | `/monitors/{id}/check` | `X-API-Key` | Enqueue an on-demand probe to Celery. Returns HTTP 202 Accepted. |

---

## Security Model

PingGuard implements defensive controls across authentication, network boundary protection, resource governance, and logging:

### 1. Static API-Key Authentication
- All `/monitors/*` routes are protected using FastAPI `APIKeyHeader`.
- Header comparison uses constant-time string comparison (`secrets.compare_digest`) on UTF-8 bytes to defend against timing attacks.
- Missing or invalid keys return HTTP 401 Unauthorized with a generic error payload. API keys are never written to logs or error messages.

### 2. SSRF Protection & DNS-Rebinding Mitigation
- Outbound probing target URLs are validated before requests are dispatched.
- Hostnames are resolved to IP addresses via asynchronous DNS lookup. All returned IPv4 and IPv6 addresses are checked against explicit CIDR blocklists covering private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), carrier-grade NAT (`100.64.0.0/10`), and cloud metadata services (`169.254.169.254`).
- **IP Pinning**: To prevent Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks, outbound HTTP connections are established directly against the validated IP literal, preserving the original hostname in the HTTP `Host` header and TLS Server Name Indication (SNI).
- **Redirect Isolation**: Automatic HTTP redirect following is disabled in the client transport. Redirect hops are resolved manually, and each intermediate destination undergoes independent DNS resolution and SSRF validation before traversal.

### 3. Resource & Memory Bounds
- Outbound HTTP response streaming enforces an absolute ceiling (`http_max_response_bytes`, default 1 MB). Sockets close immediately upon exceeding the limit.
- Probes run within an overall timeout deadline (`probe_total_timeout_seconds`, default 8.0s) managed via `asyncio.timeout`.
- Write requests are governed by fixed-window rate limiting in Redis (`rl:<key>`), returning HTTP 429 Too Many Requests with a `Retry-After` header when exceeded.

### 4. Logging & Secret Scrubbing
- URLs containing inline basic authentication credentials (e.g. `https://user:pass@example.com`) are scrubbed before persistence or logging.
- Structured JSON logs capture contextual metadata, `X-Request-ID`, and errors without logging request payloads or credentials.

---

## Project Structure

```
pingguard/
├── .github/
│   ├── dependabot.yml              # Weekly dependency update schedule
│   └── workflows/
│       └── ci.yml                  # GitHub Actions CI workflow (lint, test, build)
├── alembic/
│   ├── env.py                      # Alembic migration environment
│   └── versions/                   # Schema migration versions
├── app/
│   ├── __init__.py                 # Version declaration (1.0.0)
│   ├── config.py                   # Centralised Pydantic settings & validation
│   ├── db.py                       # SQLAlchemy async & sync session factories
│   ├── enums.py                    # MonitorStatus, MonitorMode, PingOutcome
│   ├── logging_config.py           # Structured JSON logging & request ID filter
│   ├── main.py                     # FastAPI web application & REST routes
│   ├── models.py                   # SQLAlchemy ORM models & table constraints
│   ├── net.py                      # SSRF-hardened outbound HTTP probing engine
│   ├── ratelimit.py                # Redis & in-memory fixed-window rate limiters
│   ├── schemas.py                  # Pydantic request and response schemas
│   ├── security.py                 # Constant-time API key verification
│   ├── ssrf.py                     # IP blocklists, validation & credential redaction
│   ├── status.py                   # Outcome-to-status & HTTP code classification
│   ├── tasks.py                    # Celery tasks (probe execution, data retention)
│   ├── urls.py                     # URL normalization and safe joining
│   └── worker.py                   # Celery application & Celery Beat schedule
├── tests/
│   ├── conftest.py                 # Pytest fixtures & _test database safety guard
│   ├── test_api.py                 # REST endpoint behavioural tests
│   ├── test_config.py              # Configuration & credential validation tests
│   ├── test_imports.py             # Subprocess import isolation tests
│   ├── test_logging.py             # Structured logging & X-Request-ID tests
│   ├── test_models.py              # ORM constraints & index tests
│   ├── test_net.py                 # SSRF, DNS pinning, & latency tests
│   ├── test_orchestration.py       # Health contract & configuration tests
│   ├── test_ratelimit.py           # Rate limiting & monitor capacity tests
│   ├── test_retention.py           # Data retention task & batching tests
│   ├── test_scheduler.py           # Celery Beat sweep & concurrency tests
│   ├── test_security.py            # API key authentication tests
│   ├── test_status.py              # Status mapping & HTTP classification tests
│   └── test_tasks.py               # Worker task execution & retry tests
├── .env.example                    # Environment variable template
├── .pre-commit-config.yaml         # Pre-commit hooks (ruff, gitleaks, yaml)
├── Dockerfile                      # Multi-stage production container build
├── docker-compose.yml              # 5-service orchestration definition
├── pyproject.toml                  # PEP 621 project metadata & tool configurations
├── requirements.in                 # Human-edited direct runtime dependencies
├── requirements.txt                # Fully pinned runtime dependencies with hashes
├── requirements-dev.in             # Human-edited direct dev dependencies
└── requirements-dev.txt            # Fully pinned dev dependencies with hashes
```

---

## Testing & Continuous Integration

PingGuard maintains an automated test suite executed via `pytest`.

### Database Protection Guard
Tests are physically prevented from executing against non-test databases. `tests/conftest.py` inspects `TEST_DATABASE_URL` at import time and strictly requires the database name to end with `_test`. If `TEST_DATABASE_URL` is unset or points to a non-test database, execution halts immediately with return code 2 before any database connection or model import occurs.

### Automated CI Pipeline
Every push and pull request to `main` triggers `.github/workflows/ci.yml`:
1. **Lint & Style**: Enforces clean code via `ruff check .` and formatting via `ruff format --check .`.
2. **Type Checking**: Validates static type safety across `app/` using `mypy`.
3. **Automated Testing**: Runs the complete test suite against live PostgreSQL 15 and Redis 7 service containers, enforcing code coverage reporting.
4. **Container Build**: Validates `docker-compose.yml` syntax and builds the production Docker image with cryptographic hash verification (`--require-hashes`).

---

## Known limitations

- **Single API key and single tenant**: Authentication uses one shared API key. Multi-user accounts, organization tenancy, and role-based permissions are planned for a future update.
- **Single Celery Beat scheduler**: The periodic sweep scheduler runs as a single instance; there is currently no active-active high-availability failover if the scheduler process stops.
- **No built-in alerting system**: PingGuard records uptime and latency telemetry, but external notifications (email, Discord, Slack, SMS) are not yet integrated.
- **Redis scope**: Redis is currently used solely as the Celery task broker and write rate limiter, rather than for application query caching, Pub/Sub, or Redis Streams.
- **Headless service**: PingGuard is strictly a backend REST API service; a web dashboard interface is not included in this repository.

## Design decisions

- **Decoupled API and worker fleet**: The FastAPI application only validates requests and saves data to PostgreSQL—it never pings target websites directly. All outbound HTTP probes run asynchronously in Celery workers, ensuring slow or timing-out websites never block API responses.
- **Database-driven sweeps (`FOR UPDATE SKIP LOCKED`)**: Rather than registering a separate Celery schedule for every individual monitor, Celery Beat runs a periodic sweep over PostgreSQL. Row-level locking (`FOR UPDATE SKIP LOCKED`) lets workers claim due monitors safely without duplicate checks.
- **SSRF and DNS-rebinding protection**: Target hostnames are resolved and checked against private and loopback IP blocklists before connecting. Outbound probes pin the connection directly to the validated IP address, preventing attackers from switching IP addresses between check time and connection time.

*For detailed architectural trade-offs, engineering rationale, and notes on how AI was used, see [DESIGN.md](DESIGN.md).*

---

## License

This project is licensed under the terms of the MIT license. See [LICENSE](LICENSE) for details.
