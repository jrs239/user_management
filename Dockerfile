# Define a base stage with a Debian Bookworm base image that includes the latest glibc update
FROM python:3.12-bookworm AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=true \
    PIP_DEFAULT_TIMEOUT=100 \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    QR_CODE_DIR=/myapp/qr_codes

WORKDIR /myapp

# Build deps only in base image
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies in a virtualenv
COPY requirements.txt .
RUN python -m venv /.venv \
    && . /.venv/bin/activate \
    && pip install --upgrade pip \
    && pip install -r requirements.txt

# Define a second stage for the runtime, using the slim image
FROM python:3.12-slim-bookworm AS final
RUN apt-get update && apt-get install -y --only-upgrade libc-bin && rm -rf /var/lib/apt/lists/*

# (Optional) keep libc up to date without pinning a specific version
RUN apt-get update \
    && apt-get install -y --only-upgrade libc-bin \
    && rm -rf /var/lib/apt/lists/*

# Copy the virtual environment from the base stage
COPY --from=base /.venv /.venv

# Ensure all python commands run inside the virtual environment
ENV PATH="/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    QR_CODE_DIR=/myapp/qr_codes

# Set the working directory
WORKDIR /myapp

# Create and switch to a non-root user
# (tries useradd; falls back to adduser if needed)
RUN useradd -m myuser || adduser --disabled-password --gecos "" myuser
USER myuser

# Copy application code with appropriate ownership
COPY --chown=myuser:myuser . .

# Inform Docker that the container listens on the specified port at runtime.
EXPOSE 8000

# Use ENTRYPOINT to specify the executable when the container starts.
# NOTE: --reload is for development; remove in production if you want a stable server process
ENTRYPOINT ["uvicorn", "app.main:app", "--reload", "--host", "0.0.0.0", "--port", "8000"]
