from __future__ import annotations

from pathlib import Path

from fastapi import Depends, FastAPI, Header
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .auth import permission_dependency
from .config import settings
from .control_mapper import build_coverage, summarize_frameworks
from .metrics import metrics_middleware, metrics_response
from .modeler import generate_model_graph
from .models import (
    AsyncScannerBatchRequest,
    ComplianceReleaseResponse,
    CoverageBatchRequest,
    Finding,
    GateDecision,
    GateEvaluateRequest,
    JobStatusResponse,
    ModelGenerateRequest,
    ModelGenerateResponse,
    PipelineEvent,
    RiskReleaseResponse,
    ScannerBatchIngestResponse,
    ScannerBatchRequest,
    ScannerIngestResponse,
    ScannerReportRequest,
    SbomDocument,
)
from .object_store import EvidenceStore
from .queue import JobQueue
from .risk_engine import evaluate_gate
from .scanner_adapters import parse_report
from .store import get_store

app = FastAPI(
    title="DevSecOps Visual Risk Mapper API",
    version="0.3.0",
    description="MVP API for ingestion, threat/dataflow graphing, risk evaluation, and control coverage.",
)
app.middleware("http")(metrics_middleware)

store = get_store()
job_queue = JobQueue()
evidence_store = EvidenceStore() if settings.evidence_upload_enabled else None

ui_dir = Path(__file__).resolve().parents[2] / "ui"
if ui_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(ui_dir), html=True), name="ui")


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/ui")


@app.get("/metrics")
def metrics():
    return metrics_response()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/collector/events")
def ingest_event(event: PipelineEvent, _=Depends(permission_dependency("ingest"))) -> dict[str, str]:
    store.add_event(event)
    return {"status": "accepted"}


@app.post("/api/v1/ingest/findings/batch")
def ingest_findings(findings: list[Finding], _=Depends(permission_dependency("ingest"))) -> dict[str, int]:
    count = store.add_findings(findings)
    return {"ingested": count}


def _maybe_store_evidence(tool: str, report: dict, evidence_uri: str) -> str:
    if evidence_store is None:
        return evidence_uri
    key = f"scanner-reports/{tool}/{abs(hash(evidence_uri))}.json"
    return evidence_store.put_json(key=key, payload=report)


@app.post("/api/v1/ingest/scanner/report", response_model=ScannerIngestResponse)
def ingest_scanner_report(payload: ScannerReportRequest, _=Depends(permission_dependency("ingest"))) -> ScannerIngestResponse:
    evidence_uri = _maybe_store_evidence(payload.tool, payload.report, payload.evidence_uri)
    findings = parse_report(
        tool=payload.tool,
        report=payload.report,
        asset=payload.asset,
        evidence_uri=evidence_uri,
        observed_at=payload.observed_at,
    )
    count = store.add_findings(findings)
    return ScannerIngestResponse(ingested=count, findings=findings)


@app.post("/api/v1/ingest/scanner/batch", response_model=ScannerBatchIngestResponse)
def ingest_scanner_batch(payload: ScannerBatchRequest, _=Depends(permission_dependency("ingest"))) -> ScannerBatchIngestResponse:
    all_findings: list[Finding] = []
    by_tool: dict[str, int] = {}
    for report in payload.reports:
        evidence_uri = _maybe_store_evidence(report.tool, report.report, report.evidence_uri)
        findings = parse_report(
            tool=report.tool,
            report=report.report,
            asset=report.asset,
            evidence_uri=evidence_uri,
            observed_at=report.observed_at,
        )
        all_findings.extend(findings)
        by_tool[report.tool] = by_tool.get(report.tool, 0) + len(findings)
    count = store.add_findings(all_findings)
    return ScannerBatchIngestResponse(ingested=count, by_tool=by_tool, findings=all_findings)


def _worker_async_scanner_batch(payload: dict) -> dict:
    request = AsyncScannerBatchRequest.model_validate(payload)
    all_findings: list[Finding] = []
    by_tool: dict[str, int] = {}

    for report in request.reports:
        evidence_uri = _maybe_store_evidence(report.tool, report.report, report.evidence_uri)
        findings = parse_report(
            tool=report.tool,
            report=report.report,
            asset=report.asset,
            evidence_uri=evidence_uri,
            observed_at=report.observed_at,
        )
        all_findings.extend(findings)
        by_tool[report.tool] = by_tool.get(report.tool, 0) + len(findings)

    store.add_findings(all_findings)
    decision = evaluate_gate(all_findings, request.asset_context, request.exceptions)
    store.add_release(request.release_id, decision.score, decision)

    service_id = all_findings[0].asset.service if all_findings else "unknown"
    coverage = build_coverage(
        request.release_id,
        decision,
        has_sbom=store.has_sbom(request.release_id),
        has_model=store.has_graph(service_id),
        finding_sources={f.source for f in all_findings},
    )
    store.add_coverage(request.release_id, coverage)
    return {
        "release_id": request.release_id,
        "ingested": len(all_findings),
        "by_tool": by_tool,
        "decision": decision.model_dump(mode="json"),
    }


@app.post("/api/v1/jobs/scanner/batch", response_model=JobStatusResponse)
def enqueue_scanner_batch_job(
    payload: AsyncScannerBatchRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _=Depends(permission_dependency("ingest")),
) -> JobStatusResponse:
    record = job_queue.enqueue(
        fn_name="scanner_batch_pipeline",
        payload=payload.model_dump(mode="json"),
        worker=_worker_async_scanner_batch,
        idempotency_key=idempotency_key,
    )
    return JobStatusResponse(
        job_id=record.job_id,
        status=record.status,
        attempts=record.attempts,
        max_attempts=record.max_attempts,
        idempotency_key=record.idempotency_key,
        result=record.result,
        error=record.error,
    )


@app.get("/api/v1/jobs/{job_id}", response_model=JobStatusResponse)
def get_job(job_id: str, _=Depends(permission_dependency("read"))) -> JobStatusResponse:
    record = job_queue.get(job_id)
    if record is None:
        return JobStatusResponse(job_id=job_id, status="failed", attempts=0, max_attempts=settings.max_job_retries, error="job_not_found")
    return JobStatusResponse(
        job_id=record.job_id,
        status=record.status,
        attempts=record.attempts,
        max_attempts=record.max_attempts,
        idempotency_key=record.idempotency_key,
        result=record.result,
        error=record.error,
    )


@app.post("/api/v1/ingest/sbom")
def ingest_sbom(sbom: SbomDocument, _=Depends(permission_dependency("ingest"))) -> dict[str, int | str]:
    store.add_sbom(sbom)
    return {"status": "ingested", "packages": len(sbom.packages)}


@app.post("/api/v1/model/generate", response_model=ModelGenerateResponse)
def model_generate(payload: ModelGenerateRequest, _=Depends(permission_dependency("model"))) -> ModelGenerateResponse:
    model = generate_model_graph(payload.repo, payload.commit_sha)
    service_id = payload.repo.split("/")[-1].replace(".git", "")
    store.upsert_graph(service_id, model.nodes, model.edges)
    return model


@app.post("/api/v1/gate/evaluate", response_model=GateDecision)
def gate_evaluate(payload: GateEvaluateRequest, _=Depends(permission_dependency("evaluate"))) -> GateDecision:
    decision = evaluate_gate(payload.findings, payload.asset_context, payload.exceptions)
    store.add_release(payload.release_id, decision.score, decision)
    service_id = payload.findings[0].asset.service if payload.findings else "unknown"
    coverage = build_coverage(
        payload.release_id,
        decision,
        has_sbom=store.has_sbom(payload.release_id),
        has_model=store.has_graph(service_id),
        finding_sources={f.source for f in payload.findings},
    )
    store.add_coverage(payload.release_id, coverage)
    return decision


@app.get("/api/v1/risk/release/{release_id}", response_model=RiskReleaseResponse)
def risk_release(release_id: str, _=Depends(permission_dependency("read"))) -> RiskReleaseResponse:
    release = store.get_release(release_id)
    if release is None:
        decision = GateDecision(result="warn", score=0.0, reasons=["release_not_found"], evidence=[], policy_version="unknown")
        return RiskReleaseResponse(release_id=release_id, score=0.0, decision=decision, findings=[])

    release_findings = [f for f in store.list_findings() if getattr(f, "status", "open") in {"open", "accepted_risk", "resolved"}]
    return RiskReleaseResponse(release_id=release_id, score=release.score, decision=release.decision, findings=release_findings)


@app.get("/api/v1/graph/service/{service_id}")
def graph_service(service_id: str, _=Depends(permission_dependency("read"))) -> dict:
    graph = store.get_graph(service_id)
    return {"service_id": service_id, "nodes": graph["nodes"], "edges": graph["edges"]}


@app.post("/api/v1/ingest/coverage/batch")
def ingest_coverage(payload: CoverageBatchRequest, _=Depends(permission_dependency("ingest"))) -> dict[str, int]:
    count = store.add_coverage(payload.release_id, payload.coverage)
    return {"ingested": count}


@app.get("/api/v1/compliance/release/{release_id}", response_model=ComplianceReleaseResponse)
def compliance_release(release_id: str, _=Depends(permission_dependency("read"))) -> ComplianceReleaseResponse:
    coverage = store.get_coverage(release_id)
    summary = summarize_frameworks(coverage)
    return ComplianceReleaseResponse(release_id=release_id, frameworks=summary, controls=coverage)


@app.get("/api/v1/audit")
def audit_log(_=Depends(permission_dependency("admin"))) -> dict:
    return {"entries": store.get_audit()}
