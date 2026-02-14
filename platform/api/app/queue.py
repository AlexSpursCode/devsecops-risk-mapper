from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
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


@dataclass
class JobQueue:
    max_attempts: int = settings.max_job_retries
    _jobs: dict[str, JobRecord] = field(default_factory=dict)
    _idempotency_index: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._lock = threading.Lock()

    def enqueue(self, fn_name: str, payload: dict[str, Any], worker: Callable[[dict[str, Any]], dict[str, Any]], idempotency_key: str | None = None) -> JobRecord:
        with self._lock:
            if idempotency_key and idempotency_key in self._idempotency_index:
                existing_id = self._idempotency_index[idempotency_key]
                return self._jobs[existing_id]

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
                return
            except Exception as exc:  # noqa: BLE001
                record.error = str(exc)
                if record.attempts >= record.max_attempts:
                    record.status = "failed"
                    return
                time.sleep(0.2)

    def get(self, job_id: str) -> JobRecord | None:
        with self._lock:
            return self._jobs.get(job_id)
