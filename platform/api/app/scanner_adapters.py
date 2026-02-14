from __future__ import annotations

from datetime import datetime, timezone

from .models import Asset, Finding, Severity


def _now_iso() -> datetime:
    return datetime.now(timezone.utc)


def _severity_from_text(value: str | None, default: Severity = Severity.medium) -> Severity:
    if not value:
        return default
    normalized = value.lower().strip()
    mapping = {
        "critical": Severity.critical,
        "error": Severity.high,
        "high": Severity.high,
        "warning": Severity.medium,
        "medium": Severity.medium,
        "moderate": Severity.medium,
        "low": Severity.low,
        "info": Severity.info,
    }
    return mapping.get(normalized, default)


def _severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.medium
    if score >= 9.0:
        return Severity.critical
    if score >= 7.0:
        return Severity.high
    if score >= 4.0:
        return Severity.medium
    if score > 0:
        return Severity.low
    return Severity.info


def parse_gitleaks(report: dict, asset: Asset, evidence_uri: str, observed_at: datetime | None = None) -> list[Finding]:
    ts = observed_at or _now_iso()
    entries = report.get("findings") or report.get("Leaks") or []
    findings: list[Finding] = []
    for idx, item in enumerate(entries):
        rid = item.get("RuleID", "secret")
        file_path = item.get("File", "unknown")
        line = item.get("StartLine", 0)
        findings.append(
            Finding(
                id=f"gitleaks-{rid}-{idx}",
                source="gitleaks",
                type="secret",
                severity=Severity.critical,
                asset=asset,
                evidence_uri=f"{evidence_uri}#{file_path}:{line}",
                first_seen=ts,
                last_seen=ts,
                status="open",
                exploitability=0.95,
            )
        )
    return findings


def parse_semgrep(report: dict, asset: Asset, evidence_uri: str, observed_at: datetime | None = None) -> list[Finding]:
    ts = observed_at or _now_iso()
    entries = report.get("results", [])
    findings: list[Finding] = []
    for idx, item in enumerate(entries):
        extra = item.get("extra", {})
        sev = _severity_from_text(extra.get("severity"), default=Severity.medium)
        path = item.get("path", "unknown")
        line = item.get("start", {}).get("line", 0)
        check_id = item.get("check_id", "semgrep-check")
        findings.append(
            Finding(
                id=f"semgrep-{check_id}-{idx}",
                source="semgrep",
                type="code_pattern",
                severity=sev,
                asset=asset,
                evidence_uri=f"{evidence_uri}#{path}:{line}",
                first_seen=ts,
                last_seen=ts,
                status="open",
                exploitability=0.6,
            )
        )
    return findings


def parse_checkov(report: dict, asset: Asset, evidence_uri: str, observed_at: datetime | None = None) -> list[Finding]:
    ts = observed_at or _now_iso()
    failed = report.get("results", {}).get("failed_checks", [])
    findings: list[Finding] = []
    for idx, item in enumerate(failed):
        sev = _severity_from_text(item.get("severity"), default=Severity.medium)
        check_id = item.get("check_id", "checkov-check")
        path = item.get("file_path", "unknown")
        findings.append(
            Finding(
                id=f"checkov-{check_id}-{idx}",
                source="checkov",
                type="iac_misconfig",
                severity=sev,
                asset=asset,
                evidence_uri=f"{evidence_uri}#{path}",
                first_seen=ts,
                last_seen=ts,
                status="open",
                exploitability=0.5,
            )
        )
    return findings


def parse_grype(report: dict, asset: Asset, evidence_uri: str, observed_at: datetime | None = None) -> list[Finding]:
    ts = observed_at or _now_iso()
    matches = report.get("matches", [])
    findings: list[Finding] = []
    for idx, item in enumerate(matches):
        vuln = item.get("vulnerability", {})
        artifact = item.get("artifact", {})
        vuln_id = vuln.get("id", "grype-vuln")
        sev = _severity_from_text(vuln.get("severity"), default=Severity.medium)
        pkg = artifact.get("name", "unknown")
        ver = artifact.get("version", "unknown")
        findings.append(
            Finding(
                id=f"grype-{vuln_id}-{idx}",
                source="grype",
                type="dependency_vulnerability",
                severity=sev,
                asset=asset,
                evidence_uri=f"{evidence_uri}#{pkg}:{ver}",
                first_seen=ts,
                last_seen=ts,
                status="open",
                exploitability=0.7,
            )
        )
    return findings


def parse_osv(report: dict, asset: Asset, evidence_uri: str, observed_at: datetime | None = None) -> list[Finding]:
    ts = observed_at or _now_iso()
    results = report.get("results", [])
    findings: list[Finding] = []
    for res_idx, result in enumerate(results):
        package = result.get("package", {})
        pkg_name = package.get("name", "unknown")
        vulns = result.get("vulnerabilities", [])
        for vul_idx, vuln in enumerate(vulns):
            vuln_id = vuln.get("id", "osv-vuln")
            score = None
            scores = vuln.get("severity", [])
            if scores and isinstance(scores, list):
                raw = scores[0].get("score", "")
                try:
                    score = float(str(raw).split("/")[0])
                except (ValueError, TypeError, IndexError):
                    score = None
            sev = _severity_from_cvss(score)
            findings.append(
                Finding(
                    id=f"osv-{vuln_id}-{res_idx}-{vul_idx}",
                    source="osv",
                    type="dependency_vulnerability",
                    severity=sev,
                    asset=asset,
                    evidence_uri=f"{evidence_uri}#{pkg_name}:{vuln_id}",
                    first_seen=ts,
                    last_seen=ts,
                    status="open",
                    exploitability=0.65,
                )
            )
    return findings


def parse_report(tool: str, report: dict, asset: Asset, evidence_uri: str, observed_at: datetime | None = None) -> list[Finding]:
    if tool == "gitleaks":
        return parse_gitleaks(report, asset, evidence_uri, observed_at)
    if tool == "semgrep":
        return parse_semgrep(report, asset, evidence_uri, observed_at)
    if tool == "checkov":
        return parse_checkov(report, asset, evidence_uri, observed_at)
    if tool == "grype":
        return parse_grype(report, asset, evidence_uri, observed_at)
    if tool == "osv":
        return parse_osv(report, asset, evidence_uri, observed_at)
    raise ValueError(f"unsupported tool: {tool}")
