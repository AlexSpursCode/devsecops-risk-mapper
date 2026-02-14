"""Initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-02-14 00:00:00
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=128), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "sboms",
        sa.Column("release_id", sa.String(length=128), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "coverage",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("release_id", sa.String(length=128), nullable=False),
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("covered", sa.Boolean(), nullable=False),
        sa.Column("evidence_uri", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
    )
    op.create_index("ix_coverage_release_id", "coverage", ["release_id"])
    op.create_table(
        "releases",
        sa.Column("release_id", sa.String(length=128), primary_key=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("decision_payload", sa.JSON(), nullable=False),
    )
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("pipeline_id", sa.String(length=128), nullable=False),
        sa.Column("repo", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.create_index("ix_events_pipeline_id", "events", ["pipeline_id"])
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])


def downgrade() -> None:
    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index("ix_events_pipeline_id", table_name="events")
    op.drop_table("events")
    op.drop_table("releases")
    op.drop_index("ix_coverage_release_id", table_name="coverage")
    op.drop_table("coverage")
    op.drop_table("sboms")
    op.drop_table("findings")
