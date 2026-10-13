"""
PingGuard API Application.

The API validates and stores; all outbound probes run in Celery workers.
FastAPI application entry point implementing asynchronous REST endpoints for
monitor registration, retrieval, update, listing, and on-demand checks.
"""

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from enum import Enum
from typing import Annotated

import redis.asyncio as aioredis
from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    HTTPException,
    Path,
    Query,
    Request,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.config import get_settings
from app.db import engine, get_db
from app.enums import MonitorStatus
from app.logging_config import REQUEST_ID_REGEX, configure_logging, request_id_var
from app.models import Monitor, PingResult
from app.ratelimit import rate_limit_write
from app.schemas import (
    MonitorCheckResponse,
    MonitorCreate,
    MonitorRead,
    MonitorUpdate,
    PingResultRead,
)
from app.security import require_api_key
from app.tasks import execute_ping

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize structured logging on application startup."""
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    yield


# Application metadata for OpenAPI /docs and /redoc
app = FastAPI(
    title="PingGuard API",
    description=(
        "Distributed Uptime Monitoring System.\n\n"
        "Provides non-blocking endpoints backed durably by PostgreSQL via SQLAlchemy 2.0 Async.\n"
        "Manages monitor definitions, scheduling states, and optional keep-alive parameters.\n\n"
        "**Note on Keep-Alive:** Keep-alive activity sends periodic lightweight requests "
        "to reduce idle sleeping on platforms that spin down. It is an optional activity attempt, "
        "not a provider-level guarantee of permanent uptime."
    ),
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    """
    Middleware injecting correlated request ID.
    Accepts valid incoming X-Request-ID header, otherwise generates new UUID hex.
    """
    incoming = request.headers.get("X-Request-ID")
    req_id = incoming if incoming and REQUEST_ID_REGEX.match(incoming) else uuid.uuid4().hex

    token = request_id_var.set(req_id)
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = req_id
        return response
    finally:
        request_id_var.reset(token)


if settings.cors_allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-API-Key"],
        max_age=600,
    )


async def check_database_readiness(session: AsyncSession | None = None) -> bool:
    """Probe PostgreSQL database using async session or engine with 2-second timeout."""
    try:
        async with asyncio.timeout(2.0):
            if session is not None:
                await session.execute(text("SELECT 1"))
            else:
                async with engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def check_redis_readiness() -> bool:
    """Probe Redis broker using PING with 2-second timeout."""
    try:
        async with asyncio.timeout(2.0):
            client = aioredis.from_url(settings.redis_broker_url)
            try:
                await client.ping()
            finally:
                await client.aclose()
        return True
    except Exception:
        return False


@app.get(
    "/health",
    tags=["System"],
    summary="Health check",
    description="Returns the operational status of the PingGuard API service.",
)
async def health_check() -> dict[str, str]:
    """Basic service health check endpoint for container orchestrators and uptime probes."""
    return {
        "status": "healthy",
        "service": "PingGuard API",
        "version": __version__,
    }


@app.get(
    "/ready",
    tags=["System"],
    summary="Readiness check",
    description="Verifies operational connectivity to database and Redis dependencies.",
)
async def readiness_check(
    db: Annotated[AsyncSession, Depends(get_db)],
) -> JSONResponse:
    """
    Readiness check validating downstream PostgreSQL and Redis connectivity.
    Returns HTTP 200 {'status': 'ready'} on full health,
    or HTTP 503 {'status': 'not_ready', 'failed': [...]} on dependency failure.
    """
    db_ok, redis_ok = await asyncio.gather(
        check_database_readiness(db),
        check_redis_readiness(),
    )

    if db_ok and redis_ok:
        return JSONResponse(status_code=status.HTTP_200_OK, content={"status": "ready"})

    failed: list[str] = []
    if not db_ok:
        failed.append("database")
    if not redis_ok:
        failed.append("redis")

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"status": "not_ready", "failed": failed},
    )


router = APIRouter(
    prefix="/monitors",
    tags=["Monitors"],
    dependencies=[Depends(require_api_key)],
)


@router.post(
    "/",
    response_model=MonitorRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(rate_limit_write)],
    summary="Create a new monitor",
    description=(
        "Validates and persists a new monitor endpoint in PostgreSQL with "
        "optional keep-alive settings. "
        "Initial status is set to PENDING. No outbound network probe is performed in this request."
    ),
)
async def create_monitor(
    payload: MonitorCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MonitorRead:
    """
    Asynchronously registers a target URL for monitoring and/or keep-alive in PostgreSQL.

    - Validates payload via MonitorCreate schema.
    - Enforces keep-alive configuration consistency.
    - Persists durable row in the 'monitors' table with auto-generated ID.
    - Initializes status to PENDING and marks next_check_at as due immediately.
    - Returns serialized MonitorRead.
    """
    settings = get_settings()
    count = await db.scalar(select(func.count()).select_from(Monitor))
    if count is not None and count >= settings.max_monitors:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="monitor limit reached",
        )

    now = datetime.now(UTC)

    monitor = Monitor(
        name=payload.name,
        url=str(payload.url),
        check_interval_seconds=payload.check_interval_seconds,
        status=MonitorStatus.PENDING.value,
        last_checked_at=None,
        next_check_at=now,
    )
    db.add(monitor)
    await db.commit()
    await db.refresh(monitor)
    return MonitorRead.model_validate(monitor)


@router.get(
    "/{monitor_id}",
    response_model=MonitorRead,
    summary="Get monitor by ID",
    description="Retrieves configuration and status for a single monitor from PostgreSQL.",
)
async def get_monitor(
    monitor_id: Annotated[int, Path(..., description="The unique integer ID of the monitor", ge=1)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MonitorRead:
    """
    Asynchronously fetches a monitor from PostgreSQL by its unique ID.

    Raises HTTP 404 if the monitor does not exist.
    """
    monitor = await db.get(Monitor, monitor_id)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )
    return MonitorRead.model_validate(monitor)


@router.patch(
    "/{monitor_id}",
    response_model=MonitorRead,
    dependencies=[Depends(rate_limit_write)],
    summary="Update monitor (Partial)",
    description=(
        "Partially updates an existing monitor's name, check interval, "
        "or keep-alive configuration in PostgreSQL."
    ),
)
@router.put(
    "/{monitor_id}",
    response_model=MonitorRead,
    dependencies=[Depends(rate_limit_write)],
    summary="Update monitor",
    description=(
        "Updates an existing monitor's configuration, including "
        "keep-alive parameters in PostgreSQL."
    ),
)
async def update_monitor(
    monitor_id: Annotated[int, Path(..., description="The unique integer ID of the monitor", ge=1)],
    payload: MonitorUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MonitorRead:
    """
    Asynchronously updates an existing monitor in PostgreSQL.

    Supports both PATCH and PUT semantics. Fields omitted or set to None are preserved.
    Enforces configuration consistency across the merged monitor state.
    Raises HTTP 404 if the monitor does not exist, or HTTP 422 if update creates an invalid state.
    """
    monitor = await db.get(Monitor, monitor_id)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )

    update_data = payload.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        if hasattr(monitor, key):
            val_to_set = value.value if isinstance(value, Enum) else value
            setattr(monitor, key, val_to_set)

    await db.commit()
    await db.refresh(monitor)
    return MonitorRead.model_validate(monitor)


@router.get(
    "/",
    response_model=list[MonitorRead],
    summary="List all monitors",
    description="Retrieves a paginated list of registered monitors from PostgreSQL.",
)
async def list_monitors(
    db: Annotated[AsyncSession, Depends(get_db)],
    skip: Annotated[int, Query(description="Number of records to skip (offset)", ge=0)] = 0,
    limit: Annotated[int, Query(description="Maximum records to return", ge=1, le=1000)] = 100,
) -> list[MonitorRead]:
    """
    Asynchronously retrieves a paginated slice of monitors from PostgreSQL.

    Guarded with default limit=100 to prevent unbounded database query memory allocation.
    """
    stmt = select(Monitor).order_by(Monitor.id.asc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return [MonitorRead.model_validate(m) for m in result.scalars().all()]


@router.delete(
    "/{monitor_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(rate_limit_write)],
    summary="Delete monitor",
    description="Deletes an existing monitor and all associated probe results (CASCADE).",
)
async def delete_monitor(
    monitor_id: Annotated[int, Path(..., description="The unique integer ID of the monitor", ge=1)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """
    Asynchronously deletes a monitor and all cascading results from PostgreSQL.
    """
    monitor = await db.get(Monitor, monitor_id)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )
    await db.delete(monitor)
    await db.commit()
    return None


@router.get(
    "/{monitor_id}/results",
    response_model=list[PingResultRead],
    summary="Get monitor probe results",
    description=(
        "Retrieves historical probe and keep-alive results for a monitor, "
        "ordered most recent first."
    ),
)
async def get_monitor_results(
    monitor_id: Annotated[int, Path(..., description="The unique integer ID of the monitor", ge=1)],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: Annotated[int, Query(description="Maximum results to return", ge=1, le=500)] = 50,
) -> list[PingResultRead]:
    """
    Retrieves probe execution telemetry for charting and auditing.
    """
    monitor = await db.get(Monitor, monitor_id)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )
    stmt = (
        select(PingResult)
        .where(PingResult.monitor_id == monitor_id)
        .order_by(PingResult.checked_at.desc())
        .limit(limit)
    )
    res = await db.execute(stmt)
    return [PingResultRead.model_validate(r) for r in res.scalars().all()]


@router.post(
    "/{monitor_id}/check",
    response_model=MonitorCheckResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(rate_limit_write)],
    summary="Queue on-demand probe check (results appear via GET /monitors/{id}/results)",
    description=(
        "Enqueues an immediate health probe task for the specified monitor to Celery workers. "
        "Returns HTTP 202 Accepted immediately without performing outbound network I/O in the API. "
        "Historical and latest results can be retrieved via "
        "GET /monitors/{monitor_id}/results."
    ),
)
async def trigger_monitor_check(
    monitor_id: Annotated[int, Path(..., description="The unique integer ID of the monitor", ge=1)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MonitorCheckResponse:
    """
    Asynchronously queues a health probe for the specified monitor to Celery.
    Results appear via GET /monitors/{id}/results.
    """
    monitor = await db.get(Monitor, monitor_id)
    if monitor is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitor not found",
        )
    await db.close()

    execute_ping.delay(monitor.id)
    return MonitorCheckResponse(status="queued", monitor_id=monitor.id)


app.include_router(router)
