from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from .models import ModelGenerateResponse, RiskEdge, RiskNode

TF_DATASTORE_PATTERNS = {
    'aws_db_instance': 'rds',
    'aws_rds_cluster': 'rds-cluster',
    'aws_elasticache_cluster': 'redis',
    'aws_dynamodb_table': 'dynamodb',
    'aws_s3_bucket': 's3',
    'google_sql_database_instance': 'cloudsql',
    'azurerm_postgresql_server': 'postgresql',
}

DATASTORE_ENV_HINTS = {
    'DB_HOST': 'database',
    'DATABASE_URL': 'database',
    'POSTGRES_HOST': 'postgresql',
    'MYSQL_HOST': 'mysql',
    'MONGO_URL': 'mongodb',
    'REDIS_HOST': 'redis',
    'KAFKA_BROKER': 'kafka',
    'RABBITMQ_HOST': 'rabbitmq',
    'S3_BUCKET': 'object-store',
}


def _load_yaml_documents(path: Path) -> list[dict[str, Any]]:
    try:
        content = path.read_text()
    except UnicodeDecodeError:
        return []
    try:
        docs = list(yaml.safe_load_all(content))
        return [d for d in docs if isinstance(d, dict)]
    except yaml.YAMLError:
        return []


def _node_id(node_type: str, label: str) -> str:
    clean = re.sub(r'[^a-zA-Z0-9_.-]+', '-', label.strip().lower()).strip('-')
    return f"{node_type}:{clean or 'unknown'}"


def _extract_datastores_from_env(env_items: list[dict[str, Any]] | None) -> set[str]:
    datastores: set[str] = set()
    if not env_items:
        return datastores
    for item in env_items:
        if not isinstance(item, dict):
            continue
        name = str(item.get('name', ''))
        if not name:
            continue
        for hint_key, datastore in DATASTORE_ENV_HINTS.items():
            if hint_key in name.upper():
                datastores.add(datastore)
    return datastores


def _parse_compose_file(path: Path, nodes: dict[str, RiskNode], edges: set[tuple[str, str, str]]) -> None:
    docs = _load_yaml_documents(path)
    if not docs:
        return
    compose = docs[0]
    services = compose.get('services', {}) if isinstance(compose, dict) else {}
    if not isinstance(services, dict):
        return

    for service_name, config in services.items():
        service_node = RiskNode(
            id=_node_id('service', str(service_name)),
            node_type='service',
            label=str(service_name),
            risk_score=35,
        )
        nodes[service_node.id] = service_node

        if isinstance(config, dict):
            depends_on = config.get('depends_on', [])
            if isinstance(depends_on, dict):
                depends_on = list(depends_on.keys())
            for dep in depends_on if isinstance(depends_on, list) else []:
                dep_node = RiskNode(
                    id=_node_id('service', str(dep)),
                    node_type='service',
                    label=str(dep),
                    risk_score=30,
                )
                nodes[dep_node.id] = dep_node
                edges.add((service_node.id, dep_node.id, 'calls'))

            env_value = config.get('environment', [])
            env_items: list[dict[str, Any]] = []
            if isinstance(env_value, dict):
                env_items = [{'name': k, 'value': v} for k, v in env_value.items()]
            elif isinstance(env_value, list):
                for entry in env_value:
                    if isinstance(entry, str) and '=' in entry:
                        k, v = entry.split('=', 1)
                        env_items.append({'name': k, 'value': v})

            for ds in _extract_datastores_from_env(env_items):
                ds_node = RiskNode(
                    id=_node_id('data_store', ds),
                    node_type='data_store',
                    label=ds,
                    risk_score=55,
                )
                nodes[ds_node.id] = ds_node
                edges.add((service_node.id, ds_node.id, 'writes_to'))


def _parse_k8s_file(path: Path, nodes: dict[str, RiskNode], edges: set[tuple[str, str, str]]) -> None:
    docs = _load_yaml_documents(path)
    for doc in docs:
        kind = str(doc.get('kind', '')).lower()
        metadata = doc.get('metadata', {}) if isinstance(doc.get('metadata'), dict) else {}
        name = str(metadata.get('name', '') or 'unknown')

        if kind in {'deployment', 'statefulset', 'daemonset', 'pod'}:
            service_node = RiskNode(
                id=_node_id('service', name),
                node_type='service',
                label=name,
                risk_score=38,
            )
            nodes[service_node.id] = service_node

            spec = doc.get('spec', {}) if isinstance(doc.get('spec'), dict) else {}
            template = spec.get('template', {}) if isinstance(spec.get('template'), dict) else {}
            template_spec = template.get('spec', {}) if isinstance(template.get('spec'), dict) else {}
            containers = template_spec.get('containers', []) if isinstance(template_spec.get('containers'), list) else []

            for container in containers:
                if not isinstance(container, dict):
                    continue
                env_items = container.get('env', []) if isinstance(container.get('env'), list) else []
                for ds in _extract_datastores_from_env(env_items):
                    ds_node = RiskNode(
                        id=_node_id('data_store', ds),
                        node_type='data_store',
                        label=ds,
                        risk_score=55,
                    )
                    nodes[ds_node.id] = ds_node
                    edges.add((service_node.id, ds_node.id, 'writes_to'))

        if kind == 'service':
            spec = doc.get('spec', {}) if isinstance(doc.get('spec'), dict) else {}
            svc_type = str(spec.get('type', 'ClusterIP'))
            if svc_type in {'LoadBalancer', 'NodePort'}:
                target_node = RiskNode(
                    id=_node_id('service', name),
                    node_type='service',
                    label=name,
                    risk_score=45,
                )
                nodes[target_node.id] = target_node

                threat_node = RiskNode(
                    id=_node_id('threat', 'internet-exposure'),
                    node_type='threat',
                    label='internet-exposure',
                    risk_score=70,
                )
                nodes[threat_node.id] = threat_node
                edges.add((threat_node.id, target_node.id, 'targets'))


def _parse_terraform_file(path: Path, nodes: dict[str, RiskNode], edges: set[tuple[str, str, str]]) -> None:
    try:
        content = path.read_text()
    except UnicodeDecodeError:
        return

    matches = re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', content)
    for resource_type, resource_name in matches:
        label = TF_DATASTORE_PATTERNS.get(resource_type)
        if label is None:
            continue
        ds_name = f"{label}:{resource_name}"
        ds_node = RiskNode(
            id=_node_id('data_store', ds_name),
            node_type='data_store',
            label=ds_name,
            risk_score=60,
        )
        nodes[ds_node.id] = ds_node


def _scan_repo_files(repo_path: Path, max_files: int) -> list[Path]:
    patterns = ['**/docker-compose*.yml', '**/docker-compose*.yaml', '**/*.tf', '**/*.yml', '**/*.yaml']
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in repo_path.glob(pattern):
            if path.is_file() and path not in seen:
                files.append(path)
                seen.add(path)
                if len(files) >= max_files:
                    return files
    return files


def generate_model_graph(repo: str, commit_sha: str, repo_path: str | None = None, max_files: int = 500) -> ModelGenerateResponse:
    release_id = f"{repo}:{commit_sha[:12]}"

    nodes: dict[str, RiskNode] = {}
    edges: set[tuple[str, str, str]] = set()

    if repo_path:
        root = Path(repo_path).expanduser().resolve()
    else:
        root = Path.cwd()

    scanned = 0
    if root.exists() and root.is_dir():
        for path in _scan_repo_files(root, max_files=max_files):
            scanned += 1
            lower_name = path.name.lower()
            if lower_name.startswith('docker-compose') and path.suffix in {'.yml', '.yaml'}:
                _parse_compose_file(path, nodes, edges)
            elif path.suffix == '.tf':
                _parse_terraform_file(path, nodes, edges)
            elif path.suffix in {'.yml', '.yaml'}:
                _parse_k8s_file(path, nodes, edges)

    if not nodes:
        service_id = repo.split('/')[-1].replace('.git', '')
        fallback_service = RiskNode(id=_node_id('service', service_id), node_type='service', label=service_id, risk_score=35)
        fallback_threat = RiskNode(id=_node_id('threat', 'tampering'), node_type='threat', label='tampering', risk_score=60)
        nodes[fallback_service.id] = fallback_service
        nodes[fallback_threat.id] = fallback_threat
        edges.add((fallback_threat.id, fallback_service.id, 'targets'))

    control = RiskNode(id='control:samm-des-01', node_type='control', label='Threat Assessment', risk_score=20)
    nodes[control.id] = control

    for node in list(nodes.values()):
        if node.node_type == 'service':
            edges.add((control.id, node.id, 'mitigates'))

    model_nodes = sorted(nodes.values(), key=lambda n: n.id)
    model_edges = sorted([RiskEdge(source=s, target=t, relation=r) for s, t, r in edges], key=lambda e: (e.source, e.target, e.relation))

    # attach extraction metadata as synthetic threat node for quick observability
    metadata_node = RiskNode(
        id=_node_id('threat', f'extractor-scanned-files-{scanned}'),
        node_type='threat',
        label=f'extractor-scanned-files-{scanned}',
        risk_score=5,
    )
    model_nodes.append(metadata_node)

    return ModelGenerateResponse(release_id=release_id, nodes=model_nodes, edges=model_edges)
