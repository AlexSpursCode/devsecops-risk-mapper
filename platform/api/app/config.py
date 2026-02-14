import os
import secrets
from pathlib import Path


class Settings:
    storage_backend: str = os.getenv("STORAGE_BACKEND", "memory")
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://devsecops@localhost:5432/devsecops")
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = ""
    object_store_endpoint: str = os.getenv("OBJECT_STORE_ENDPOINT", "http://localhost:9000")
    object_store_access_key: str = ""
    object_store_secret_key: str = ""
    object_store_bucket: str = os.getenv("OBJECT_STORE_BUCKET", "devsecops-evidence")
    evidence_upload_enabled: bool = os.getenv("EVIDENCE_UPLOAD_ENABLED", "false").lower() == "true"
    auth_mode: str = os.getenv("AUTH_MODE", "jwt")
    auth_allow_insecure_header: bool = os.getenv("AUTH_ALLOW_INSECURE_HEADER", "false").lower() == "true"
    auth_jwt_secret: str = ""
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

    def __init__(self) -> None:
        self.neo4j_password = self._read_secret("NEO4J_PASSWORD")
        self.object_store_access_key = self._read_secret("OBJECT_STORE_ACCESS_KEY")
        self.object_store_secret_key = self._read_secret("OBJECT_STORE_SECRET_KEY")
        # Generate ephemeral JWT secret only for local runs when not explicitly configured.
        self.auth_jwt_secret = self._read_secret("AUTH_JWT_SECRET", generate_if_missing=True)
        self._validate()

    @staticmethod
    def _read_secret(env_key: str, generate_if_missing: bool = False) -> str:
        file_key = f"{env_key}_FILE"
        file_path = os.getenv(file_key)
        if file_path:
            content = Path(file_path).expanduser().read_text().strip()
            if content:
                return content
        value = os.getenv(env_key, "").strip()
        if value:
            return value
        if generate_if_missing:
            return secrets.token_urlsafe(48)
        return ""

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        normalized = value.lower()
        return any(token in normalized for token in ["change-me", "replace-with", "<strong-"])

    def _validate(self) -> None:
        if self.storage_backend == "postgres" and self._is_placeholder(self.database_url):
            raise ValueError("DATABASE_URL contains placeholder credentials; set a real connection string")
        if self.storage_backend == "postgres" and not self.neo4j_password:
            raise ValueError("NEO4J_PASSWORD (or NEO4J_PASSWORD_FILE) is required for postgres backend")
        if self.evidence_upload_enabled and (not self.object_store_access_key or not self.object_store_secret_key):
            raise ValueError("OBJECT_STORE_ACCESS_KEY/OBJECT_STORE_SECRET_KEY (or *_FILE) are required when evidence upload is enabled")
        if self.auth_mode == "jwt" and self._is_placeholder(self.auth_jwt_secret):
            raise ValueError("AUTH_JWT_SECRET contains placeholder text; set a strong secret or AUTH_JWT_SECRET_FILE")

settings = Settings()
