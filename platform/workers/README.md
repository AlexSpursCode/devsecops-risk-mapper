# Workers

This folder holds async worker adapters for scanner parsing and normalization.

Planned adapters:

- gitleaks -> Finding[]
- semgrep -> Finding[]
- checkov -> Finding[]
- grype/osv -> Finding[]
- syft -> SbomDocument

Current utility:

- `ingest_scanners.py`: reads scanner artifact JSON files, calls `/api/v1/ingest/scanner/report`, and outputs `normalized-findings.json` for gate evaluation.
