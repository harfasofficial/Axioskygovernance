FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Create non-root user
RUN groupadd -r axiosky && useradd -r -g axiosky axiosky

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Set permissions
RUN chown -R axiosky:axiosky /app
USER axiosky

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# NOTE: Migrations are intentionally NOT run here.
# Run migrations separately: docker-compose run --rm migrate
# This prevents race conditions in multi-replica deployments.
#
# Gunicorn manages workers properly (graceful shutdown, worker recycling).
# uvicorn workers handle async; gunicorn handles process management.
CMD ["gunicorn", "governor.service:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "--bind", "0.0.0.0:8000", "--timeout", "30", "--graceful-timeout", "10"]
