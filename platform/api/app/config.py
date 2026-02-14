import os


class Settings:
    storage_backend: str = os.getenv("STORAGE_BACKEND", "memory")
    database_url: str = os.getenv("DATABASE_URL", "postgresql+psycopg://devsecops:devsecops@localhost:5432/devsecops")
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    neo4j_user: str = os.getenv("NEO4J_USER", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "devsecopsneo")
    object_store_endpoint: str = os.getenv("OBJECT_STORE_ENDPOINT", "http://localhost:9000")
    object_store_access_key: str = os.getenv("OBJECT_STORE_ACCESS_KEY", "minioadmin")
    object_store_secret_key: str = os.getenv("OBJECT_STORE_SECRET_KEY", "minioadmin")
    object_store_bucket: str = os.getenv("OBJECT_STORE_BUCKET", "devsecops-evidence")
    evidence_upload_enabled: bool = os.getenv("EVIDENCE_UPLOAD_ENABLED", "false").lower() == "true"
    auth_mode: str = os.getenv("AUTH_MODE", "header")
    auth_jwt_secret: str = os.getenv("AUTH_JWT_SECRET", "devsecops-local-secret")
    auth_jwt_algorithm: str = os.getenv("AUTH_JWT_ALGORITHM", "HS256")
    max_job_retries: int = int(os.getenv("MAX_JOB_RETRIES", "3"))


settings = Settings()
