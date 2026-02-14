# Modeler

This component converts repository and IaC metadata into dataflow and threat model graph nodes/edges.

Current implementation in `platform/api/app/modeler.py` extracts model metadata from:

- Docker Compose files (`docker-compose*.yml|yaml`)
- Kubernetes manifests (`*.yml|*.yaml`, multi-doc supported)
- Terraform files (`*.tf`)

`/api/v1/model/generate` accepts optional:

- `repo_path`: filesystem path to scan
- `max_files`: upper bound for file scan
