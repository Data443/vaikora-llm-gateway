# Data443 LLM Gateway - Dockerfile

FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

# Copy application code
COPY config/ ./config/
COPY gateway/ ./gateway/

# Create __init__.py files for proper Python package structure
RUN touch gateway/__init__.py config/__init__.py

# Create non-root runtime user for container hardening
RUN groupadd --system app && useradd --system --gid app --create-home --home-dir /home/app app \
    && chown -R app:app /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV LOG_LEVEL=INFO
# prometheus_client multiprocess mode: each worker writes its metric values here and
# GET /metrics aggregates them. Emptied by the CMD below on every container start.
ENV PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus-multiproc

# Drop root privileges for runtime
USER app

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health')" || exit 1

# Run the application. Empty the metrics dir first (counters from a previous run of this
# container must not be summed in), then exec so uvicorn stays PID 1 and gets signals.
CMD ["sh", "-c", "mkdir -p \"$PROMETHEUS_MULTIPROC_DIR\" && find \"$PROMETHEUS_MULTIPROC_DIR\" -mindepth 1 -delete && exec uvicorn gateway.main:app --host 0.0.0.0 --port 8000"]
