from .models import ModelGenerateResponse, RiskEdge, RiskNode


def generate_model_graph(repo: str, commit_sha: str) -> ModelGenerateResponse:
    release_id = f"{repo}:{commit_sha[:12]}"
    service_id = repo.split("/")[-1].replace(".git", "")

    nodes = [
        RiskNode(id=f"service:{service_id}", node_type="service", label=service_id, risk_score=40),
        RiskNode(id=f"datastore:{service_id}-db", node_type="data_store", label=f"{service_id}-db", risk_score=55),
        RiskNode(id=f"control:SAMM-DES-01", node_type="control", label="Threat Assessment", risk_score=20),
        RiskNode(id=f"threat:tampering", node_type="threat", label="Tampering", risk_score=60),
    ]

    edges = [
        RiskEdge(source=f"service:{service_id}", target=f"datastore:{service_id}-db", relation="writes_to"),
        RiskEdge(source=f"threat:tampering", target=f"service:{service_id}", relation="targets"),
        RiskEdge(source=f"control:SAMM-DES-01", target=f"service:{service_id}", relation="mitigates"),
    ]

    return ModelGenerateResponse(release_id=release_id, nodes=nodes, edges=edges)
