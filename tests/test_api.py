import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi.testclient import TestClient

from app.main import app
from app.config import settings


client = TestClient(app)


def headers(role: str = "platform_admin") -> dict[str, str]:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "role": role,
        "iss": settings.auth_jwt_issuer,
        "aud": settings.auth_jwt_audience,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp()),
    }
    token = jwt.encode(payload, settings.auth_jwt_secret, algorithm=settings.auth_jwt_algorithm)
    return {"Authorization": f"Bearer {token}"}


def base_finding(fid: str = "F-1", severity: str = "critical") -> dict:
    now = datetime.now(tz=timezone.utc).isoformat()
    return {
        "id": fid,
        "source": "gitleaks",
        "type": "secret",
        "severity": severity,
        "asset": {
            "repo": "gitlab.example.com/acme/payments",
            "service": "payments-api",
            "owner": "payments",
            "environment": "prod",
            "criticality": "tier1",
            "data_classification": "confidential",
        },
        "evidence_uri": "https://evidence.local/finding/F-1",
        "first_seen": now,
        "last_seen": now,
        "status": "open",
        "exploitability": 0.9,
        "compensating_controls": 0,
    }


def test_health() -> None:
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_ingest_and_evaluate_warn_only() -> None:
    findings = [base_finding()]
    ingest = client.post("/api/v1/ingest/findings/batch", json=findings, headers=headers())
    assert ingest.status_code == 200
    assert ingest.json()["ingested"] == 1

    payload = {
        "release_id": "rel-100",
        "findings": findings,
        "asset_context": {
            "internet_facing": True,
            "environment": "prod",
            "data_classification": "confidential",
        },
        "exceptions": [],
    }
    gate = client.post("/api/v1/gate/evaluate", json=payload, headers=headers())
    assert gate.status_code == 200
    body = gate.json()
    assert body["result"] == "warn"
    assert body["score"] >= 50
    assert body["policy_version"] == "mvp-warn-only-v1"


def test_model_and_graph_read() -> None:
    model = client.post(
        "/api/v1/model/generate",
        json={"repo": "gitlab.example.com/acme/payments.git", "commit_sha": "abcdeffedcba123456789"},
        headers=headers("security_architect"),
    )
    assert model.status_code == 200
    graph = client.get("/api/v1/graph/service/payments", headers=headers("auditor"))
    assert graph.status_code == 200
    assert len(graph.json()["nodes"]) >= 1


def test_compliance_endpoint() -> None:
    sbom = {
        "release_id": "rel-101",
        "format": "cyclonedx",
        "artifact_uri": "https://evidence.local/sbom/rel-101",
        "packages": [{"name": "fastapi", "version": "0.115.6", "ecosystem": "pypi"}],
    }
    client.post("/api/v1/ingest/sbom", json=sbom, headers=headers())

    payload = {
        "release_id": "rel-101",
        "findings": [base_finding(fid="F-2", severity="low")],
        "asset_context": {
            "internet_facing": False,
            "environment": "staging",
            "data_classification": "internal",
        },
        "exceptions": [],
    }
    client.post("/api/v1/gate/evaluate", json=payload, headers=headers())

    compliance = client.get("/api/v1/compliance/release/rel-101", headers=headers("auditor"))
    assert compliance.status_code == 200
    data = compliance.json()
    assert "SAMM" in data["frameworks"]
    assert "CISA" in data["frameworks"]
    assert len(data["controls"]) >= 3


def test_exception_reduces_score() -> None:
    finding = base_finding(fid="F-3", severity="high")
    payload = {
        "release_id": "rel-200",
        "findings": [finding],
        "asset_context": {
            "internet_facing": True,
            "environment": "prod",
            "data_classification": "confidential",
        },
        "exceptions": [
            {
                "finding_id": "F-3",
                "owner": "arch",
                "approved": True,
                "expires_at": (datetime.now(tz=timezone.utc) + timedelta(days=10)).isoformat(),
            }
        ],
    }
    gate = client.post("/api/v1/gate/evaluate", json=payload, headers=headers())
    assert gate.status_code == 200
    body = gate.json()
    assert body["score"] == 0
    assert body["result"] == "pass"


def test_rbac_forbidden() -> None:
    res = client.get("/api/v1/audit", headers=headers("auditor"))
    assert res.status_code == 403


def test_ingest_scanner_report_gitleaks() -> None:
    payload = {
        "tool": "gitleaks",
        "asset": {
            "repo": "gitlab.example.com/acme/payments",
            "service": "payments-api",
            "owner": "payments",
            "environment": "prod",
            "criticality": "tier1",
            "data_classification": "confidential",
        },
        "evidence_uri": "https://evidence.local/scans/gitleaks.json",
        "report": {
            "findings": [
                {
                    "RuleID": "generic-api-key",
                    "File": "app/config.py",
                    "StartLine": 22,
                }
            ]
        },
    }
    res = client.post("/api/v1/ingest/scanner/report", json=payload, headers=headers())
    assert res.status_code == 200
    body = res.json()
    assert body["ingested"] == 1
    assert body["findings"][0]["source"] == "gitleaks"
    assert body["findings"][0]["type"] == "secret"
    assert body["findings"][0]["severity"] == "critical"


def test_ingest_scanner_batch_multi_tool() -> None:
    base_asset = {
        "repo": "gitlab.example.com/acme/checkout",
        "service": "checkout-api",
        "owner": "checkout",
        "environment": "prod",
        "criticality": "tier1",
        "data_classification": "confidential",
    }
    payload = {
        "reports": [
            {
                "tool": "semgrep",
                "asset": base_asset,
                "evidence_uri": "https://evidence.local/scans/semgrep.json",
                "report": {
                    "results": [
                        {
                            "check_id": "python.lang.security.audit.eval-detected",
                            "path": "src/main.py",
                            "start": {"line": 15},
                            "extra": {"severity": "ERROR"},
                        }
                    ]
                },
            },
            {
                "tool": "checkov",
                "asset": base_asset,
                "evidence_uri": "https://evidence.local/scans/checkov.json",
                "report": {
                    "results": {
                        "failed_checks": [
                            {
                                "check_id": "CKV_AWS_20",
                                "file_path": "terraform/main.tf",
                                "severity": "HIGH",
                            }
                        ]
                    }
                },
            },
            {
                "tool": "grype",
                "asset": base_asset,
                "evidence_uri": "https://evidence.local/scans/grype.json",
                "report": {
                    "matches": [
                        {
                            "vulnerability": {"id": "CVE-2026-1111", "severity": "High"},
                            "artifact": {"name": "openssl", "version": "3.0.0"},
                        }
                    ]
                },
            },
        ]
    }
    res = client.post("/api/v1/ingest/scanner/batch", json=payload, headers=headers())
    assert res.status_code == 200
    body = res.json()
    assert body["ingested"] == 3
    assert body["by_tool"]["semgrep"] == 1
    assert body["by_tool"]["checkov"] == 1
    assert body["by_tool"]["grype"] == 1
    sources = sorted([item["source"] for item in body["findings"]])
    assert sources == ["checkov", "grype", "semgrep"]


def test_async_scanner_batch_job() -> None:
    asset = {
        "repo": "gitlab.example.com/acme/ledger",
        "service": "ledger-api",
        "owner": "ledger",
        "environment": "prod",
        "criticality": "tier1",
        "data_classification": "confidential",
    }
    payload = {
        "release_id": "rel-async-1",
        "asset_context": {
            "internet_facing": True,
            "environment": "prod",
            "data_classification": "confidential",
        },
        "exceptions": [],
        "reports": [
            {
                "tool": "gitleaks",
                "asset": asset,
                "evidence_uri": "https://evidence.local/async/gitleaks.json",
                "report": {"findings": [{"RuleID": "hardcoded", "File": "src/a.py", "StartLine": 2}]},
            }
        ],
    }
    enqueue = client.post(
        "/api/v1/jobs/scanner/batch",
        json=payload,
        headers={**headers(), "Idempotency-Key": "idem-async-1"},
    )
    assert enqueue.status_code == 200
    job_id = enqueue.json()["job_id"]

    final = None
    for _ in range(30):
        status = client.get(f"/api/v1/jobs/{job_id}", headers=headers("auditor"))
        assert status.status_code == 200
        body = status.json()
        if body["status"] in {"completed", "failed"}:
            final = body
            break
        time.sleep(0.05)
    assert final is not None
    assert final["status"] == "completed"
    assert final["result"]["ingested"] == 1


def test_metrics_endpoint() -> None:
    res = client.get("/metrics", headers=headers("auditor"))
    assert res.status_code == 200
    assert "devsecops_api_requests_total" in res.text


def test_model_extraction_from_real_iac(tmp_path) -> None:
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        """
services:
  api:
    image: ghcr.io/acme/api:latest
    depends_on:
      - redis
    environment:
      - DB_HOST=postgres
      - REDIS_HOST=redis
  redis:
    image: redis:7
"""
    )
    k8s = tmp_path / "deployment.yaml"
    k8s.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments
spec:
  template:
    spec:
      containers:
        - name: payments
          image: acme/payments:1.0
          env:
            - name: DATABASE_URL
              value: postgresql://db
---
apiVersion: v1
kind: Service
metadata:
  name: payments
spec:
  type: LoadBalancer
"""
    )
    tf = tmp_path / "main.tf"
    tf.write_text(
        """
resource "aws_s3_bucket" "evidence" {}
resource "aws_db_instance" "primary" {}
"""
    )

    payload = {
        "repo": "gitlab.example.com/acme/payments.git",
        "commit_sha": "abcdef1234567890",
        "repo_path": str(tmp_path),
        "max_files": 100,
    }
    model = client.post("/api/v1/model/generate", json=payload, headers=headers("security_architect"))
    assert model.status_code == 200
    body = model.json()

    node_ids = {n["id"] for n in body["nodes"]}
    edge_triplets = {(e["source"], e["target"], e["relation"]) for e in body["edges"]}

    assert "service:api" in node_ids
    assert "service:payments" in node_ids
    assert any(n.startswith("data_store:database") or n.startswith("data_store:rds") for n in node_ids)
    assert any(n.startswith("data_store:redis") for n in node_ids)
    assert any(n.startswith("data_store:s3-evidence") for n in node_ids)
    assert ("service:api", "service:redis", "calls") in edge_triplets
    assert any(rel == "mitigates" for _, _, rel in edge_triplets)
