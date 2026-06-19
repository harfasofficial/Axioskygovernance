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
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run migration first, then start the API with multiple workers
CMD ["sh", "-c", "python -m database.migrate && uvicorn governor.service:app --host 0.0.0.0 --port 8000 --workers 2"]
