FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SENTINELOPS_DATASET_PATH=/app/evals/incidents.json \
    SENTINELOPS_DB_PATH=/data/sentinelops.db

WORKDIR /app

RUN addgroup --system sentinelops \
    && adduser --system --ingroup sentinelops --home /nonexistent sentinelops

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip install --disable-pip-version-check .

COPY evals ./evals
RUN mkdir /data && chown sentinelops:sentinelops /data

USER sentinelops
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"

CMD ["uvicorn", "sentinelops.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
