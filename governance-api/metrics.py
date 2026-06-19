# metrics.py
"""
Prometheus metrics integration.
Call setup_metrics(app) once during app initialization.

Exposes /metrics endpoint with:
- HTTP request duration histograms (p50, p95, p99)
- Request count by status code and endpoint
- In-flight request gauge

Compatible with Grafana, Datadog, and any Prometheus-compatible backend.
"""
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi import FastAPI


def setup_metrics(app: FastAPI) -> None:
    """
    Attach Prometheus metrics instrumentation to the FastAPI app.
    Exposes /metrics endpoint automatically.
    """
    Instrumentator(
        should_group_status_codes=False,
        should_ignore_untemplated=True,
        should_respect_env_var=True,
        should_instrument_requests_inprogress=True,
        excluded_handlers=["/health", "/metrics"],
        inprogress_name="axiosky_inprogress_requests",
        inprogress_labels=True,
    ).instrument(app).expose(app, include_in_schema=False, tags=["observability"])
