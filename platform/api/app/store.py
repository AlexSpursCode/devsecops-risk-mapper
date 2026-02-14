from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from neo4j import GraphDatabase
from sqlalchemy import JSON, Boolean, DateTime, Float, String, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .config import settings
from .db import engine, session_scope
from .models import Coverage, GateDecision, PipelineEvent, RiskEdge, RiskNode, SbomDocument


class Base(DeclarativeBase):
    pass


class FindingRow(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class SbomRow(Base):
    __tablename__ = "sboms"
    release_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class CoverageRow(Base):
    __tablename__ = "coverage"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    release_id: Mapped[str] = mapped_column(String(128), index=True)
    control_id: Mapped[str] = mapped_column(String(128))
    covered: Mapped[bool] = mapped_column(Boolean)
    evidence_uri: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)


class ReleaseRow(Base):
    __tablename__ = "releases"
    release_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    score: Mapped[float] = mapped_column(Float)
    decision_payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class EventRow(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    pipeline_id: Mapped[str] = mapped_column(String(128), index=True)
    repo: Mapped[str] = mapped_column(Text)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON)


class AuditRow(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


@dataclass
class ReleaseRecord:
    release_id: str
    score: float
    decision: GateDecision


class Store(ABC):
    @abstractmethod
    def add_audit(self, action: str, details: dict[str, Any]) -> None:
        raise NotImplementedError

    @abstractmethod
    def add_event(self, event: PipelineEvent) -> None:
        raise NotImplementedError

    @abstractmethod
    def add_findings(self, rows: Iterable) -> int:
        raise NotImplementedError

    @abstractmethod
    def list_findings(self) -> list:
        raise NotImplementedError

    @abstractmethod
    def add_sbom(self, sbom: SbomDocument) -> None:
        raise NotImplementedError

    @abstractmethod
    def has_sbom(self, release_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def add_coverage(self, release_id: str, rows: list[Coverage]) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_coverage(self, release_id: str) -> list[Coverage]:
        raise NotImplementedError

    @abstractmethod
    def add_release(self, release_id: str, score: float, decision: GateDecision) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_release(self, release_id: str) -> ReleaseRecord | None:
        raise NotImplementedError

    @abstractmethod
    def upsert_graph(self, service_id: str, nodes: list[RiskNode], edges: list[RiskEdge]) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_graph(self, service_id: str) -> dict[str, list]:
        raise NotImplementedError

    @abstractmethod
    def has_graph(self, service_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_audit(self) -> list[dict[str, Any]]:
        raise NotImplementedError


@dataclass
class InMemoryStore(Store):
    findings: list = field(default_factory=list)
    sboms: dict[str, SbomDocument] = field(default_factory=dict)
    coverage: dict[str, list[Coverage]] = field(default_factory=dict)
    releases: dict[str, ReleaseRecord] = field(default_factory=dict)
    graph: dict[str, dict[str, list]] = field(default_factory=dict)
    events: list[PipelineEvent] = field(default_factory=list)
    audit_log: list[dict] = field(default_factory=list)

    def add_audit(self, action: str, details: dict[str, Any]) -> None:
        self.audit_log.append({"action": action, "details": details})

    def add_event(self, event: PipelineEvent) -> None:
        self.events.append(event)
        self.add_audit("collector_event", {"pipeline_id": event.pipeline_id, "repo": event.repo})

    def add_findings(self, rows: Iterable) -> int:
        batch = list(rows)
        self.findings.extend(batch)
        self.add_audit("ingest_findings", {"count": len(batch)})
        return len(batch)

    def list_findings(self) -> list:
        return self.findings

    def add_sbom(self, sbom: SbomDocument) -> None:
        self.sboms[sbom.release_id] = sbom
        self.add_audit("ingest_sbom", {"release_id": sbom.release_id, "packages": len(sbom.packages)})

    def has_sbom(self, release_id: str) -> bool:
        return release_id in self.sboms

    def add_coverage(self, release_id: str, rows: list[Coverage]) -> int:
        self.coverage[release_id] = rows
        self.add_audit("coverage_update", {"release_id": release_id, "count": len(rows)})
        return len(rows)

    def get_coverage(self, release_id: str) -> list[Coverage]:
        return self.coverage.get(release_id, [])

    def add_release(self, release_id: str, score: float, decision: GateDecision) -> None:
        self.releases[release_id] = ReleaseRecord(release_id=release_id, score=score, decision=decision)
        self.add_audit("gate_evaluate", {"release_id": release_id, "score": score, "result": decision.result})

    def get_release(self, release_id: str) -> ReleaseRecord | None:
        return self.releases.get(release_id)

    def upsert_graph(self, service_id: str, nodes: list[RiskNode], edges: list[RiskEdge]) -> None:
        self.graph[service_id] = {"nodes": nodes, "edges": edges}
        self.add_audit("graph_update", {"service_id": service_id, "nodes": len(nodes), "edges": len(edges)})

    def get_graph(self, service_id: str) -> dict[str, list]:
        return self.graph.get(service_id, {"nodes": [], "edges": []})

    def has_graph(self, service_id: str) -> bool:
        graph = self.graph.get(service_id)
        return bool(graph and graph.get("nodes"))

    def get_audit(self) -> list[dict[str, Any]]:
        return self.audit_log


class PersistentStore(Store):
    def __init__(self) -> None:
        Base.metadata.create_all(engine)
        self.neo = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password))

    def add_audit(self, action: str, details: dict[str, Any]) -> None:
        with session_scope() as session:
            session.add(AuditRow(action=action, details=details))

    def add_event(self, event: PipelineEvent) -> None:
        payload = event.model_dump(mode="json")
        with session_scope() as session:
            session.add(EventRow(pipeline_id=event.pipeline_id, repo=event.repo, payload=payload))
            session.add(AuditRow(action="collector_event", details={"pipeline_id": event.pipeline_id, "repo": event.repo}))

    def add_findings(self, rows: Iterable) -> int:
        batch = list(rows)
        with session_scope() as session:
            for row in batch:
                payload = row.model_dump(mode="json")
                session.merge(FindingRow(id=row.id, payload=payload))
            session.add(AuditRow(action="ingest_findings", details={"count": len(batch)}))
        return len(batch)

    def list_findings(self) -> list:
        with session_scope() as session:
            rows = session.execute(select(FindingRow)).scalars().all()
        from .models import Finding

        return [Finding.model_validate(r.payload) for r in rows]

    def add_sbom(self, sbom: SbomDocument) -> None:
        payload = sbom.model_dump(mode="json")
        with session_scope() as session:
            session.merge(SbomRow(release_id=sbom.release_id, payload=payload))
            session.add(AuditRow(action="ingest_sbom", details={"release_id": sbom.release_id, "packages": len(sbom.packages)}))

    def has_sbom(self, release_id: str) -> bool:
        with session_scope() as session:
            row = session.get(SbomRow, release_id)
        return row is not None

    def add_coverage(self, release_id: str, rows: list[Coverage]) -> int:
        with session_scope() as session:
            existing = session.execute(select(CoverageRow).where(CoverageRow.release_id == release_id)).scalars().all()
            for row in existing:
                session.delete(row)
            for row in rows:
                session.add(
                    CoverageRow(
                        release_id=release_id,
                        control_id=row.control_id,
                        covered=row.covered,
                        evidence_uri=row.evidence_uri,
                        confidence=row.confidence,
                    )
                )
            session.add(AuditRow(action="coverage_update", details={"release_id": release_id, "count": len(rows)}))
        return len(rows)

    def get_coverage(self, release_id: str) -> list[Coverage]:
        with session_scope() as session:
            rows = session.execute(select(CoverageRow).where(CoverageRow.release_id == release_id)).scalars().all()
        return [
            Coverage(
                release_id=r.release_id,
                control_id=r.control_id,
                covered=r.covered,
                evidence_uri=r.evidence_uri,
                confidence=r.confidence,
            )
            for r in rows
        ]

    def add_release(self, release_id: str, score: float, decision: GateDecision) -> None:
        with session_scope() as session:
            session.merge(
                ReleaseRow(
                    release_id=release_id,
                    score=score,
                    decision_payload=decision.model_dump(mode="json"),
                )
            )
            session.add(AuditRow(action="gate_evaluate", details={"release_id": release_id, "score": score, "result": decision.result}))

    def get_release(self, release_id: str) -> ReleaseRecord | None:
        with session_scope() as session:
            row = session.get(ReleaseRow, release_id)
        if row is None:
            return None
        return ReleaseRecord(release_id=row.release_id, score=row.score, decision=GateDecision.model_validate(row.decision_payload))

    def upsert_graph(self, service_id: str, nodes: list[RiskNode], edges: list[RiskEdge]) -> None:
        with self.neo.session() as session:
            session.run("MATCH (n {service_id: $service_id}) DETACH DELETE n", service_id=service_id)
            for node in nodes:
                session.run(
                    "CREATE (n:RiskNode {service_id: $service_id, id: $id, node_type: $node_type, label: $label, risk_score: $risk_score})",
                    service_id=service_id,
                    id=node.id,
                    node_type=node.node_type,
                    label=node.label,
                    risk_score=node.risk_score,
                )
            for edge in edges:
                session.run(
                    "MATCH (a:RiskNode {service_id: $service_id, id: $source}), (b:RiskNode {service_id: $service_id, id: $target}) "
                    "CREATE (a)-[:REL {relation: $relation}]->(b)",
                    service_id=service_id,
                    source=edge.source,
                    target=edge.target,
                    relation=edge.relation,
                )
        self.add_audit("graph_update", {"service_id": service_id, "nodes": len(nodes), "edges": len(edges)})

    def get_graph(self, service_id: str) -> dict[str, list]:
        with self.neo.session() as session:
            node_res = session.run(
                "MATCH (n:RiskNode {service_id: $service_id}) RETURN n.id AS id, n.node_type AS node_type, n.label AS label, n.risk_score AS risk_score",
                service_id=service_id,
            )
            edge_res = session.run(
                "MATCH (a:RiskNode {service_id: $service_id})-[r:REL]->(b:RiskNode {service_id: $service_id}) "
                "RETURN a.id AS source, b.id AS target, r.relation AS relation",
                service_id=service_id,
            )
            nodes = [RiskNode(**record.data()) for record in node_res]
            edges = [RiskEdge(**record.data()) for record in edge_res]
        return {"nodes": nodes, "edges": edges}

    def has_graph(self, service_id: str) -> bool:
        with self.neo.session() as session:
            res = session.run(
                "MATCH (n:RiskNode {service_id: $service_id}) RETURN count(n) AS cnt",
                service_id=service_id,
            )
            count = res.single()["cnt"]
        return count > 0

    def get_audit(self) -> list[dict[str, Any]]:
        with session_scope() as session:
            rows = session.execute(select(AuditRow).order_by(AuditRow.id.asc())).scalars().all()
        return [{"action": r.action, "details": r.details, "created_at": r.created_at.isoformat()} for r in rows]


def get_store() -> Store:
    if settings.storage_backend == "postgres":
        return PersistentStore()
    return InMemoryStore()
