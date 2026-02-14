from __future__ import annotations

import json

import boto3
from botocore.client import Config

from .config import settings


class EvidenceStore:
    def __init__(self) -> None:
        self.client = boto3.client(
            "s3",
            endpoint_url=settings.object_store_endpoint,
            aws_access_key_id=settings.object_store_access_key,
            aws_secret_access_key=settings.object_store_secret_key,
            config=Config(signature_version="s3v4"),
            region_name="us-east-1",
        )
        self.bucket = settings.object_store_bucket

    def put_json(self, key: str, payload: dict) -> str:
        body = json.dumps(payload).encode("utf-8")
        self.client.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json")
        return f"s3://{self.bucket}/{key}"
