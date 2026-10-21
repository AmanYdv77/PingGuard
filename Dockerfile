# ==============================================================================
# PingGuard — Multi-Stage Application Dockerfile
#
# Shared application image for:
#   1. web       (FastAPI HTTP Control Plane)
#   2. worker    (Celery Probing Fleet Data Plane)
#   3. scheduler (Celery Beat Scheduling Heartbeat)
#
# Multi-stage build isolates build tooling (gcc, dev headers) from the runtime
# image, minimizing image surface area, removing dev tooling vulnerabilities,
# and enforcing non-root user execution (UID 1000).
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build & Dependency Wheel Cache
# ------------------------------------------------------------------------------
FROM python:3.13-slim AS builder

WORKDIR /build

# Install compilation headers for native C extensions (psycopg2, asyncpg)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only dependency declarations to maximize Docker layer caching
COPY requirements.txt .

# Install dependencies into the user local directory for clean multi-stage transfer
RUN pip install --user --no-cache-dir --require-hashes -r requirements.txt

# ------------------------------------------------------------------------------
# Stage 2: Final Minimal Runtime Container
# ------------------------------------------------------------------------------
FROM python:3.13-slim AS runtime

WORKDIR /app

# Ensure Python unbuffered stdout/stderr and prevent bytecode generation
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/appuser/.local/bin:$PATH"

# Install minimal runtime shared libraries and curl for lightweight healthchecks
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user for non-root security boundaries
RUN useradd -u 1000 -m -s /bin/bash appuser \
    && mkdir -p /app \
    && chown -R appuser:appuser /app

# Copy compiled dependencies from builder stage into appuser directory
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Copy application source code with unprivileged ownership
COPY --chown=appuser:appuser . /app

# Drop root privileges
USER appuser

# Expose FastAPI default port
EXPOSE 8000

# Default command: FastAPI Uvicorn Server (overridden by worker and scheduler in Compose)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
