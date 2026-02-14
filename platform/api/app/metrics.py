from __future__ import annotations

import time

from fastapi import Request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response

REQUEST_COUNT = Counter(
    "devsecops_api_requests_total",
    "Total API requests",
    ["method", "path", "status"],
)
REQUEST_LATENCY = Histogram(
    "devsecops_api_request_duration_seconds",
    "Request latency in seconds",
    ["method", "path"],
)


async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    route = request.url.path
    REQUEST_COUNT.labels(method=request.method, path=route, status=str(response.status_code)).inc()
    REQUEST_LATENCY.labels(method=request.method, path=route).observe(duration)
    return response


def metrics_response() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
