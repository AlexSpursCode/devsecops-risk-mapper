import os


class Settings:
    storage_backend: str = os.getenv("STORAGE_BACKEND", "memory")
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://devsecops:devsecops@localhost:5432/devsecops")
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "change-me")
    object_store_endpoint: str = os.getenv("OBJECT_STORE_ENDPOINT", "http://localhost:9000")
    object_store_access_key: str = os.getenv("OBJECT_STORE_ACCESS_KEY", "change-me")
    object_store_secret_key: str = os.getenv("OBJECT_STORE_SECRET_KEY", "change-me")
    object_store_bucket: str = os.getenv("OBJECT_STORE_BUCKET", "devsecops-evidence")
    evidence_upload_enabled: bool = os.getenv("EVIDENCE_UPLOAD_ENABLED", "false").lower() == "true"
    auth_mode: str = os.getenv("AUTH_MODE", "jwt")
    auth_allow_insecure_header: bool = os.getenv("AUTH_ALLOW_INSECURE_HEADER", "false").lower() == "true"
    auth_jwt_secret: str = os.getenv("AUTH_JWT_SECRET", "replace-with-strong-secret")
    auth_jwt_algorithm: str = os.getenv("AUTH_JWT_ALGORITHM", "HS256")
    auth_jwt_issuer: str = os.getenv("AUTH_JWT_ISSUER", "devsecops")
    auth_jwt_audience: str = os.getenv("AUTH_JWT_AUDIENCE", "devsecops-api")
    auth_jwt_leeway_seconds: int = int(os.getenv("AUTH_JWT_LEEWAY_SECONDS", "30"))
    max_job_retries: int = int(os.getenv("MAX_JOB_RETRIES", "3"))
    max_job_queue_size: int = int(os.getenv("MAX_JOB_QUEUE_SIZE", "1000"))
    max_reports_per_job: int = int(os.getenv("MAX_REPORTS_PER_JOB", "50"))
    max_report_bytes: int = int(os.getenv("MAX_REPORT_BYTES", "1048576"))
    job_retention_seconds: int = int(os.getenv("JOB_RETENTION_SECONDS", "3600"))
    metrics_public: bool = os.getenv("METRICS_PUBLIC", "false").lower() == "true"


settings = Settings()
