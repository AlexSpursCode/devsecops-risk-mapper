CREATE TABLE IF NOT EXISTS findings (
    id VARCHAR(128) PRIMARY KEY,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sboms (
    release_id VARCHAR(128) PRIMARY KEY,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS coverage (
    id BIGSERIAL PRIMARY KEY,
    release_id VARCHAR(128) NOT NULL,
    control_id VARCHAR(128) NOT NULL,
    covered BOOLEAN NOT NULL,
    evidence_uri TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_coverage_release_id ON coverage (release_id);

CREATE TABLE IF NOT EXISTS releases (
    release_id VARCHAR(128) PRIMARY KEY,
    score DOUBLE PRECISION NOT NULL,
    decision_payload JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    pipeline_id VARCHAR(128) NOT NULL,
    repo TEXT NOT NULL,
    payload JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_pipeline_id ON events (pipeline_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(128) NOT NULL,
    details JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
