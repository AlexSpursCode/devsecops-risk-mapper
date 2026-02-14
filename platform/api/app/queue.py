from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from .config import settings


@dataclass
class JobRecord:
    job_id: str
    status: str
    attempts: int
    max_attempts: int
    fn_name: str
    payload: dict[str, Any]
    idempotency_key: str | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None


@dataclass
class JobQueue:
    max_attempts: int = settings.max_job_retries
    max_queue_size: int = settings.max_job_queue_size
    retention_seconds: int = settings.job_retention_seconds
    _jobs: dict[str, JobRecord] = field(default_factory=dict)
    _idempotency_index: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._lock = threading.Lock()

    def enqueue(self, fn_name: str, payload: dict[str, Any], worker: Callable[[dict[str, Any]], dict[str, Any]], idempotency_key: str | None = None) -> JobRecord:
        with self._lock:
            self._cleanup_locked()
            if idempotency_key and idempotency_key in self._idempotency_index:
                existing_id = self._idempotency_index[idempotency_key]
                return self._jobs[existing_id]
            if len(self._jobs) >= self.max_queue_size:
                raise RuntimeError("job_queue_capacity_exceeded")

            job_id = str(uuid.uuid4())
            record = JobRecord(
                job_id=job_id,
                status="queued",
                attempts=0,
                max_attempts=self.max_attempts,
                fn_name=fn_name,
                payload=payload,
                idempotency_key=idempotency_key,
            )
            self._jobs[job_id] = record
            if idempotency_key:
                self._idempotency_index[idempotency_key] = job_id

        self._executor.submit(self._run_job, record, worker)
        return record

    def _run_job(self, record: JobRecord, worker: Callable[[dict[str, Any]], dict[str, Any]]) -> None:
        while record.attempts < record.max_attempts:
            try:
                record.status = "running" if record.attempts == 0 else "retrying"
                record.attempts += 1
                record.result = worker(record.payload)
                record.status = "completed"
                record.error = None
                record.finished_at = datetime.now(timezone.utc)
                return
            except Exception as exc:  # noqa: BLE001
                record.error = str(exc)
                if record.attempts >= record.max_attempts:
                    record.status = "failed"
                    record.finished_at = datetime.now(timezone.utc)
                    return
                time.sleep(0.2)

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            self._cleanup_locked()
            return self._jobs.get(job_id)

    def _cleanup_locked(self) -> None:
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        for job_id, record in self._jobs.items():
            if record.finished_at is None:
                continue
            age = (now - record.finished_at).total_seconds()
            if age > self.retention_seconds:
                expired.append(job_id)
        for job_id in expired:
            record = self._jobs.pop(job_id, None)
            if record and record.idempotency_key:
                self._idempotency_index.pop(record.idempotency_key, None)
