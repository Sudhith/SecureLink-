# SecureLink AI — Production Dockerfile
#
# Multi-stage build: keeps the final image lean.
# Based on Python 3.12 slim (smaller than full image).

FROM python:3.12-slim AS builder

WORKDIR /app

# Install system dependencies for python-whois, lxml, xgboost
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a virtual environment
COPY requirements.txt requirements-linux.txt ./
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements-linux.txt

# ── Final image ────────────────────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# Runtime system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy project files
COPY . .

# ── Directory structure ────────────────────────────────────────────────────────
# Data: mount a Railway Volume to /data and set DATABASE_PATH=/data/securelink.db
# See README for Railway deployment instructions.
RUN mkdir -p data/raw data/processed models

# ── Train model if not already present ────────────────────────────────────────
# The training script generates a synthetic model on first run if no CSV is found.
# For production: pre-train locally and commit models/ (or bake into image).
RUN python scripts/train_model.py || echo "Warning: model training failed at build time"

# ── Environment variables ─────────────────────────────────────────────────────
# These are defaults — override with real values in Railway/Render env panel.
ENV PORT=8000
ENV LOG_LEVEL=INFO
ENV DATABASE_PATH=/data/securelink.db

EXPOSE $PORT

# ── Startup command ────────────────────────────────────────────────────────────
# Uses uvicorn with a single worker (SQLite doesn't support multi-process writes).
# In webhook mode, FastAPI handles Telegram updates; bot uses no long-poll thread.
CMD ["sh", "-c", "uvicorn app.api:app --host 0.0.0.0 --port $PORT --workers 1"]
