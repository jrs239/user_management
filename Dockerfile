# syntax=docker/dockerfile:1.7

############################
# Build stage
############################
FROM python:3.12-bookworm AS build

# Environment settings for Python and pip
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=on

WORKDIR /app

# Install build dependencies (compiler, PostgreSQL headers)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies into a dedicated virtual environment
COPY requirements.txt .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt


############################
# Runtime stage
############################
FROM python:3.12-slim-bookworm AS final

# Keep libc/glibc up to date to avoid vulnerabilities
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade libc-bin \
 && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from build stage
COPY --from=build /opt/venv /opt/venv

# Environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    QR_CODE_DIR=/app/qr_codes

WORKDIR /app

# Create and use a non-root user for security
RUN useradd -m -u 1000 appuser
USER appuser

# Copy application source code
COPY --chown=appuser:appuser . .

# Expose application port
EXPOSE 8000

# Default command to run the app
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
