# syntax=docker/dockerfile:1.7

############################
# Build stage
############################
FROM python:3.12-bookworm AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on

WORKDIR /app

# Build requirements (compiler, pg headers) – only in build stage
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Install Python deps into a self-contained virtualenv
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt


############################
# Runtime stage
############################
FROM python:3.12-slim-bookworm AS final

# Keep libc/glibc up to date (no version pin -> no downgrades)
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade libc-bin \
 && rm -rf /var/lib/apt/lists/*

# Use the venv from the build stage
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    QR_CODE_DIR=/app/qr_codes

WORKDIR /app

# Non-root user
RUN useradd -m -u 1000 appuser
USER appuser

# App source
COPY --chown=appuser:appuser . .

EXPOSE 8000

# Production server (remove --reload)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
