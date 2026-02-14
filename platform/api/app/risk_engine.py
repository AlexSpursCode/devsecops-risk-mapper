from datetime import datetime, timezone

from .models import AssetContext, Finding, GateDecision, RiskException

POLICY_VERSION = "mvp-warn-only-v1"

SEVERITY_BASE = {
    "critical": 45,
    "high": 30,
    "medium": 18,
    "low": 8,
    "info": 3,
}

EXPOSURE_WEIGHTS = {
    "internet_facing": 12,
    "prod": 12,
    "staging": 6,
    "dev": 2,
}

DATA_BLAST = {
    "restricted": 20,
    "confidential": 15,
    "internal": 8,
    "public": 3,
}


def _has_approved_exception(finding_id: str, exceptions: list[RiskException]) -> bool:
    now = datetime.now(timezone.utc)
    for item in exceptions:
        expiry = item.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        else:
            expiry = expiry.astimezone(timezone.utc)

        if item.finding_id == finding_id and item.approved and expiry > now:
            return True
    return False


def calculate_score(findings: list[Finding], asset: AssetContext, exceptions: list[RiskException]) -> tuple[float, list[str], list[str]]:
    total = 0.0
    reasons: list[str] = []
    evidence: list[str] = []

    for finding in findings:
        if finding.status != "open":
            continue
        if _has_approved_exception(finding.id, exceptions):
            reasons.append(f"exception_active:{finding.id}")
            continue

        base = SEVERITY_BASE[finding.severity.value]
        exploitability = 20 * finding.exploitability
        exposure = EXPOSURE_WEIGHTS[asset.environment] + (EXPOSURE_WEIGHTS["internet_facing"] if asset.internet_facing else 0)
        blast = DATA_BLAST[asset.data_classification]
        deduction = min(finding.compensating_controls, 30)
        finding_score = max(0.0, base + exploitability + exposure + blast - deduction)

        total += finding_score
        reasons.append(f"open_{finding.severity.value}:{finding.id}")
        evidence.append(finding.evidence_uri)

    score = min(total, 100.0)
    return score, sorted(set(reasons)), sorted(set(evidence))


def evaluate_gate(findings: list[Finding], asset: AssetContext, exceptions: list[RiskException]) -> GateDecision:
    score, reasons, evidence = calculate_score(findings, asset, exceptions)

    if score >= 50:
        result = "warn"
        if not reasons:
            reasons = ["warn_threshold_reached"]
    else:
        result = "pass"
        if not reasons:
            reasons = ["no_open_risks"]

    # MVP is warn-only by design; block is intentionally disabled for this phase.
    return GateDecision(result=result, score=round(score, 2), reasons=reasons, evidence=evidence, policy_version=POLICY_VERSION)
