from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Role(str, Enum):
    security_architect = "security_architect"
    appsec_engineer = "appsec_engineer"
    dev_lead = "dev_lead"
    auditor = "auditor"
    platform_admin = "platform_admin"


class Asset(BaseModel):
    repo: str
    service: str
    owner: str
    environment: str
    criticality: Literal["tier0", "tier1", "tier2", "tier3"]
    data_classification: Literal["public", "internal", "confidential", "restricted"]


class Finding(BaseModel):
    id: str
    source: str
    type: str
    severity: Severity
    asset: Asset
    evidence_uri: str
    first_seen: datetime
    last_seen: datetime
    status: Literal["open", "accepted_risk", "resolved"] = "open"
    exploitability: float = Field(default=0.5, ge=0.0, le=1.0)
    compensating_controls: float = Field(default=0.0, ge=0.0, le=100.0)


class SbomPackage(BaseModel):
    name: str
    version: str
    ecosystem: Literal["npm", "pypi", "maven", "container", "other"]


class SbomDocument(BaseModel):
    release_id: str
    format: Literal["cyclonedx", "spdx"]
    artifact_uri: str
    packages: list[SbomPackage]


class Control(BaseModel):
    control_id: str
    framework: Literal["SAMM", "CISA"]
    objective: str
    automated_checks: list[str]
    required_evidence: list[str]
    coverage_rules: str


class Coverage(BaseModel):
    release_id: str
    control_id: str
    covered: bool
    evidence_uri: str
    confidence: float = Field(ge=0.0, le=1.0)


class CoverageBatchRequest(BaseModel):
    release_id: str
    coverage: list[Coverage]


class RiskNode(BaseModel):
    id: str
    node_type: Literal["service", "data_store", "control", "finding", "threat"]
    label: str
    risk_score: float = Field(ge=0.0, le=100.0)


class RiskEdge(BaseModel):
    source: str
    target: str
    relation: str


class ScannerReportRequest(BaseModel):
    tool: Literal["gitleaks", "semgrep", "checkov", "grype", "osv"]
    asset: Asset
    report: dict[str, Any]
    evidence_uri: str
    observed_at: datetime | None = None


class ScannerBatchRequest(BaseModel):
    reports: list[ScannerReportRequest]


class ScannerIngestResponse(BaseModel):
    ingested: int
    findings: list[Finding]


class ScannerBatchIngestResponse(BaseModel):
    ingested: int
    by_tool: dict[str, int]
    findings: list[Finding]


class JobStatusResponse(BaseModel):
    job_id: str
    status: Literal["queued", "running", "retrying", "completed", "failed"]
    attempts: int
    max_attempts: int
    idempotency_key: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime | None = None
    finished_at: datetime | None = None


class PipelineEvent(BaseModel):
    repo: str
    commit_sha: str
    pipeline_id: str
    mr_id: str | None = None
    branch: str
    artifacts: list[str]
    timestamp: datetime


class AssetContext(BaseModel):
    internet_facing: bool = True
    environment: Literal["dev", "staging", "prod"] = "prod"
    data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal"


class RiskException(BaseModel):
    finding_id: str
    owner: str
    expires_at: datetime
    approved: bool = False


class AsyncScannerBatchRequest(BaseModel):
    release_id: str
    reports: list[ScannerReportRequest] = Field(min_length=1, max_length=50)
    asset_context: AssetContext
    exceptions: list[RiskException] = []


class GateEvaluateRequest(BaseModel):
    release_id: str
    findings: list[Finding]
    asset_context: AssetContext
    exceptions: list[RiskException] = []


class GateDecision(BaseModel):
    result: Literal["pass", "warn", "block"]
    score: float = Field(ge=0.0, le=100.0)
    reasons: list[str]
    evidence: list[str]
    policy_version: str


class ModelGenerateRequest(BaseModel):
    repo: str
    commit_sha: str


class ModelGenerateResponse(BaseModel):
    release_id: str
    nodes: list[RiskNode]
    edges: list[RiskEdge]


class RiskReleaseResponse(BaseModel):
    release_id: str
    score: float
    decision: GateDecision
    findings: list[Finding]


class ComplianceReleaseResponse(BaseModel):
    release_id: str
    frameworks: dict[str, dict[str, Any]]
    controls: list[Coverage]
