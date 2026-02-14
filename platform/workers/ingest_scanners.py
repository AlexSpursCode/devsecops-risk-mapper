#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def post_json(url: str, payload: dict, role: str) -> dict:
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "x-role": role},
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def load_json(path: Path) -> dict:
    with path.open() as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description="Ingest scanner artifacts via DevSecOps API and emit normalized findings.")
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--role", default="platform_admin")
    parser.add_argument("--repo", required=True)
    parser.add_argument("--service", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--environment", required=True)
    parser.add_argument("--criticality", default="tier1")
    parser.add_argument("--data-classification", default="confidential")
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help="tool=path pair; supported tools: gitleaks, semgrep, checkov, grype, osv",
    )
    args = parser.parse_args()

    asset = {
        "repo": args.repo,
        "service": args.service,
        "owner": args.owner,
        "environment": args.environment,
        "criticality": args.criticality,
        "data_classification": args.data_classification,
    }

    all_findings: list[dict] = []
    for pair in args.input:
        if "=" not in pair:
            raise ValueError(f"invalid --input value: {pair}")
        tool, path_str = pair.split("=", 1)
        path = Path(path_str)
        if not path.exists():
            print(f"skip missing artifact for tool={tool}: {path}")
            continue

        report = load_json(path)
        payload = {
            "tool": tool,
            "asset": asset,
            "report": report,
            "evidence_uri": f"file://{path.resolve()}",
        }
        endpoint = f"{args.api_base.rstrip('/')}/api/v1/ingest/scanner/report"
        try:
            response = post_json(endpoint, payload, args.role)
        except (HTTPError, URLError) as exc:
            print(f"failed ingest for tool={tool}: {exc}", file=sys.stderr)
            return 1

        findings = response.get("findings", [])
        all_findings.extend(findings)
        print(f"ingested tool={tool} findings={len(findings)}")

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(all_findings, indent=2))
    print(f"wrote normalized findings: {out} count={len(all_findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
