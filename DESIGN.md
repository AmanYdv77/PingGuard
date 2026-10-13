# PingGuard Design Notes

## 1. What problem this solves

PingGuard provides lightweight uptime and health monitoring for web services. Developers deploying web applications need a reliable, SSRF-safe way to track uptime, measure latency, and detect outages without freezing API threads or risking server-side request forgery. PingGuard handles this safely with a decoupled API and background worker fleet.

## 2. Architecture in one paragraph

PingGuard is split into an API, a database, a message broker, and a worker fleet. FastAPI serves as the asynchronous control plane, saving monitor configurations to PostgreSQL without making outbound network calls. Celery Beat periodically sweeps PostgreSQL using row-level locking (`FOR UPDATE SKIP LOCKED`) to claim due monitors and dispatch jobs to Redis. Celery workers consume tasks from Redis, run SSRF-safe HTTP probes, and record latency and status back to PostgreSQL.

## 3. Key decisions

### Decision 1: Why the API and workers are separate processes
- **Choice**: Separate FastAPI from the Celery worker fleet.
- **Alternatives considered**: Probing websites directly inside FastAPI request handlers.
- **Why I chose this**: External network probes face unpredictable delays, DNS timeouts, and dead servers. Running probes inside API requests holds database connections open and can freeze the API. Decoupling ensures the API responds in milliseconds while workers absorb network delays.
- **Trade-off**: Requires running and monitoring Redis and Celery.

### Decision 2: Why PostgreSQL decides what is due (FOR UPDATE SKIP LOCKED)
- **Choice**: Celery Beat runs one periodic sweep over PostgreSQL every 15 seconds.
- **Alternatives considered**: Registering a separate Celery schedule for every individual monitor.
- **Why I chose this**: Celery Beat is meant for static schedules; dynamically managing thousands of individual schedules causes race conditions and memory bloat. PostgreSQL already indexes `next_check_at`, and `FOR UPDATE SKIP LOCKED` lets multiple workers claim due monitors without duplicate pings.
- **Trade-off**: Adds a periodic database read query every 15 seconds.

### Decision 3: Why the worker uses synchronous DB sessions while the API is async
- **Choice**: Celery tasks use synchronous SQLAlchemy sessions (`psycopg2`), while FastAPI uses `asyncpg`.
- **Alternatives considered**: Running an `asyncio` event loop inside Celery worker tasks.
- **Why I chose this**: Celery's execution model is fundamentally synchronous. Forcing an event loop inside Celery tasks creates lifecycle bugs and connection leaks. Synchronous sessions in workers are simple and reliable.
- **Trade-off**: The app maintains two PostgreSQL drivers (`asyncpg` and `psycopg2-binary`).

### Decision 4: Why acks_late and a prefetch multiplier of 1
- **Choice**: Celery tasks use `acks_late=True` and `worker_prefetch_multiplier=1`.
- **Alternatives considered**: Default early acknowledgment (`acks_early`) and default prefetch buffer.
- **Why I chose this**: With early ack, if a worker crashes mid-probe, the task is lost forever and the monitor gets stuck. With `acks_late=True`, Redis only acknowledges the task after database commit succeeds; if a worker dies, the task is redelivered. A prefetch of 1 stops workers from hoarding slow probes.
- **Trade-off**: Tasks must be idempotent because crashes can cause a probe to re-run.

### Decision 5: Multi-layer SSRF protection and its boundary
- **Choice**: Pre-resolve hostnames, block private/loopback/cloud metadata CIDRs, pin connections directly to the validated IP literal (preserving `Host` and SNI headers), and validate every redirect hop.
- **Alternatives considered**: Relying on standard HTTP clients or validating hostnames without IP pinning.
- **Why I chose this**: Standard checks allow DNS rebinding (TOCTOU attacks), where a domain returns a safe public IP on check #1 and `127.0.0.1` on check #2. Pinning the TCP connection to the validated IP closes this vulnerability completely.
- **What it does NOT cover**: It does not inspect response content or protect against malicious payloads from legitimate public servers.

### Decision 6: Status classification rules and why 4xx is 'degraded'
- **Choice**: 2xx/3xx map to `UP`, 4xx maps to `DEGRADED`, and 5xx/timeouts/errors map to `DOWN`.
- **Alternatives considered**: Treating all 4xx responses as `DOWN`.
- **Why I chose this**: A 4xx response (like 401 or 403) proves the server, network routing, and web application are alive, but the probe lacks credentials or hit a protected path. It is marked `DEGRADED` to distinguish it from complete server crashes (`DOWN`).
- **Would I change it?**: In a future version, I would let users configure expected status codes per monitor.

### Decision 7: Single static API key instead of user accounts
- **Choice**: Protect all monitor routes with a single pre-shared `X-API-Key` compared in constant time (`secrets.compare_digest`).
- **Alternatives considered**: Multi-user accounts with JWT and passwords.
- **Why I chose this**: PingGuard is designed as internal, self-hosted infrastructure. A pre-shared key gives instant protection without database user tables, password hashing, or session management.
- **Trade-off**: Single-tenant only; revoking the key affects all clients.

## 4. Known limitations

- **Single API key and single tenant**: Uses one shared API key; no multi-user accounts or role-based permissions yet.
- **Single Celery Beat scheduler**: Runs as a single instance; no active-active failover if the scheduler stops.
- **No built-in alerting system**: Records uptime and latency metrics, but external alerts (email, Slack, webhooks) are not yet integrated.
- **Redis scope**: Used only as a task queue and rate limiter, not for general caching or pub/sub.
- **Headless service**: Currently a backend REST API without an included web dashboard.

## 5. What I would do next

1. **Frontend dashboard**: Build a clean web dashboard (React/Next.js) with real-time uptime status cards and latency charts.
2. **Webhook & alert delivery**: Trigger external webhooks, Slack messages, or emails when a monitor changes state.
3. **Multi-tenant accounts**: Add organization accounts, user permissions, and JWT authentication.
4. **Prometheus metrics**: Expose a `/metrics` endpoint with latency percentiles (p50, p95, p99) and active monitor counts.
5. **Custom status code rules**: Let users specify expected HTTP codes per monitor (e.g., expecting 200 or 401).

## 6. How I used AI

I used an AI coding assistant to help build and refine PingGuard. Rather than accepting unchecked code, I verified every change by writing tests first, reviewing every diff manually, and testing against real containers.
