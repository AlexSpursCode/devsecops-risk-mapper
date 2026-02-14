# Architecture Overview

## Pipeline Flow

1. GitLab CI produces scanner artifacts and SBOM.
2. Collector ingests pipeline metadata and artifact links.
3. Analyzer components normalize findings.
4. Risk engine computes release score and decision.
5. Control mapper computes SAMM/CISA control coverage.
6. API exposes risk, graph, compliance, and audit outputs.
7. Async job queue endpoints run scanner-batch pipelines with retries and idempotency keys.
8. Prometheus metrics expose request/error/latency telemetry.

## Core Components

- Collector (`/api/v1/collector/events`)
- Ingestion APIs (`/api/v1/ingest/*`)
- Async pipeline jobs (`/api/v1/jobs/*`)
- Model generation (`/api/v1/model/generate`)
- Gate evaluation (`/api/v1/gate/evaluate`)
- Reporting APIs (`/api/v1/risk/*`, `/api/v1/graph/*`, `/api/v1/compliance/*`)
- Metrics (`/metrics`)
- UI (`/ui`)
