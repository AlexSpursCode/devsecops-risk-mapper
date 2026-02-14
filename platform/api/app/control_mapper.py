from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Coverage, GateDecision

CATALOG_PATH = Path(__file__).resolve().parents[2] / "docs" / "control-catalog.yaml"


def load_catalog() -> list[dict[str, Any]]:
    if not CATALOG_PATH.exists():
        return []
    data = yaml.safe_load(CATALOG_PATH.read_text()) or {}
    return data.get("controls", [])


def _evaluate_control(control_id: str, context: dict[str, Any]) -> tuple[bool, str, float]:
    if control_id == "CISA-SBD-01":
        covered = context.get("decision") in {"pass", "warn", "block"}
        return covered, "internal://gate/decision", 0.95 if covered else 0.3
    if control_id == "CISA-SBD-02":
        covered = context.get("has_sbom", False)
        return covered, "internal://sbom/latest" if covered else "internal://sbom/missing", 0.9 if covered else 0.4
    if control_id == "SAMM-DES-01":
        covered = context.get("has_model", False)
        return covered, "internal://model/latest" if covered else "internal://model/missing", 0.88 if covered else 0.35
    if control_id == "SAMM-VER-01":
        covered = context.get("has_findings", False)
        return covered, "internal://scan/summary", 0.92 if covered else 0.4
    if control_id == "SAMM-GOV-01":
        return True, "internal://policy/governance", 0.8
    return False, "internal://control/unknown", 0.2


def build_coverage(
    release_id: str,
    decision: GateDecision,
    has_sbom: bool,
    has_model: bool,
    finding_sources: set[str] | None = None,
) -> list[Coverage]:
    catalog = load_catalog()
    context = {
        "decision": decision.result,
        "has_sbom": has_sbom,
        "has_model": has_model,
        "has_findings": bool(finding_sources),
        "finding_sources": sorted(finding_sources or set()),
    }

    if not catalog:
        return [
            Coverage(
                release_id=release_id,
                control_id="CISA-SBD-01",
                covered=True,
                evidence_uri="internal://gate/decision",
                confidence=0.95,
            )
        ]

    controls: list[Coverage] = []
    for control in catalog:
        control_id = control.get("control_id", "UNKNOWN")
        covered, evidence_uri, confidence = _evaluate_control(control_id, context)
        controls.append(
            Coverage(
                release_id=release_id,
                control_id=control_id,
                covered=covered,
                evidence_uri=evidence_uri,
                confidence=confidence,
            )
        )
    return controls


def summarize_frameworks(coverage: list[Coverage]) -> dict[str, dict[str, float]]:
    frameworks = {
        "SAMM": {"covered": 0, "total": 0},
        "CISA": {"covered": 0, "total": 0},
    }
    for row in coverage:
        framework = "SAMM" if row.control_id.startswith("SAMM") else "CISA"
        frameworks[framework]["total"] += 1
        if row.covered:
            frameworks[framework]["covered"] += 1

    for fw, stats in frameworks.items():
        total = stats["total"] or 1
        stats["percent"] = round((stats["covered"] / total) * 100, 2)
    return frameworks
