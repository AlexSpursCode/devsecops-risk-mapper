# DevSecOps Visual Risk Mapper

Greenfield MVP implementation for a CI/CD-integrated DevSecOps risk mapper aligned to OWASP SAMM and CISA Secure by Design.

## Implemented MVP Components

- FastAPI backend with ingest, risk, graph, compliance, and gate endpoints.
- Canonical JSON schemas for core contracts.
- Warn-only risk gate with reason codes.
- Control catalog and automated control coverage mapping.
- GitLab CI pipeline with precheck, scan, sbom, evaluate, report stages.
- Kubernetes deployment/service manifests.
- Persistent backend option: PostgreSQL + Neo4j + S3-compatible object store.
- Async job API for scanner ingestion + risk evaluation with retry/idempotency.
- Optional JWT auth mode, Prometheus metrics endpoint, and UI dashboard.

## Repository Layout

- `platform/api`: API and domain logic.
- `platform/workers`: worker stubs and event contract docs.
- `platform/modeler`: DFD/threat model generation stubs.
- `platform/risk-engine`: risk scoring service logic.
- `platform/control-mapper`: SAMM/CISA coverage logic.
- `platform/policy`: OPA/Rego gate policy.
- `platform/graph`: graph mapping helpers.
- `platform/schemas`: JSON schemas.
- `platform/docs`: architecture and control catalog.
- `platform/infra`: Kubernetes and SQL artifacts.
- `tests`: unit/integration tests.

## Local Run (Memory Backend)

```bash
cd /Users/alejandroaucestovar/Desktop/devsecops
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r platform/api/requirements.txt
PYTHONPATH=platform/api uvicorn app.main:app --reload
```

## Local Run (Persistent Backend)

```bash
cd /Users/alejandroaucestovar/Desktop/devsecops
docker compose up -d postgres neo4j minio minio-init
source .venv/bin/activate
export STORAGE_BACKEND=postgres
export DATABASE_URL='postgresql+psycopg://devsecops:devsecops@localhost:5432/devsecops'
export NEO4J_URI='bolt://localhost:7687'
export NEO4J_USER='neo4j'
export NEO4J_PASSWORD='devsecopsneo'
export OBJECT_STORE_ENDPOINT='http://localhost:9000'
export OBJECT_STORE_ACCESS_KEY='minioadmin'
export OBJECT_STORE_SECRET_KEY='minioadmin'
export OBJECT_STORE_BUCKET='devsecops-evidence'
PYTHONPATH=platform/api uvicorn app.main:app --reload
```

## Optional Auth Mode (JWT)

```bash
export AUTH_MODE=jwt
export AUTH_JWT_SECRET='replace-with-strong-secret'
export AUTH_JWT_ALGORITHM='HS256'
export AUTH_JWT_ISSUER='devsecops'
export AUTH_JWT_AUDIENCE='devsecops-api'
```

JWT payload must include `role` with one of:
`security_architect`, `appsec_engineer`, `dev_lead`, `auditor`, `platform_admin`.

Security default:
- Header auth is disabled unless `AUTH_ALLOW_INSECURE_HEADER=true`.
- `/metrics` is protected unless `METRICS_PUBLIC=true`.

## Async Job Endpoints

- `POST /api/v1/jobs/scanner/batch`
- `GET /api/v1/jobs/{job_id}`

Provide `Idempotency-Key` header to deduplicate retried submissions.
Queue safety limits are configurable with:
- `MAX_JOB_QUEUE_SIZE`
- `MAX_REPORTS_PER_JOB`
- `MAX_REPORT_BYTES`
- `JOB_RETENTION_SECONDS`

## Metrics

- `GET /metrics` (Prometheus format)
- `GET /ui` (minimal operational dashboard)

## Migrations (Alembic)

```bash
cd /Users/alejandroaucestovar/Desktop/devsecops/platform/api
source ../../.venv/bin/activate
PYTHONPATH=. alembic -c alembic.ini upgrade head
```

## Run Tests

```bash
cd /Users/alejandroaucestovar/Desktop/devsecops
source .venv/bin/activate
PYTHONPATH=platform/api pytest -q tests
```
