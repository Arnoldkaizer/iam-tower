"""CloudTrail log ingestion: file, S3 bucket, and live lookup.

Local ingestion: parses CloudTrail records into SecurityEvent objects without
calling any external AI service. Exposes the entry points the orchestrator
uses:

- `ingest_file(path)` - read a local CloudTrail JSON / Gzip file
- `ingest_s3(bucket, prefix, max_files)` - read CloudTrail logs from S3
- `ingest_live_lookup(start_time, max_results, region)` - call lookup_events
"""

from __future__ import annotations

import gzip
import io
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from ..events.models import (
    Action,
    Actor,
    EventResult,
    EventSource,
    Resource,
    SecurityEvent,
    SourceNetwork,
)

logger = logging.getLogger(__name__)


class LocalIngestion:
    """Ingest CloudTrail logs and normalize to SecurityEvent objects."""

    def __init__(self, boto3_session: Any | None = None) -> None:
        self._session = boto3_session
        self._s3_client: Any | None = None
        self._ct_client: Any | None = None

    @property
    def session(self) -> Any:
        if self._session is None:
            self._session = boto3.Session()
        return self._session

    @property
    def s3(self) -> Any:
        if self._s3_client is None:
            self._s3_client = self.session.client("s3")
        return self._s3_client

    @property
    def cloudtrail(self) -> Any:
        if self._ct_client is None:
            self._ct_client = self.session.client("cloudtrail")
        return self._ct_client

    # ---- Public API ---------------------------------------------------------

    def ingest_records(self, records: list[dict[str, Any]]) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        for record in records:
            event = self._parse_record(record)
            if event is not None:
                events.append(event)
        return events

    def ingest_file(self, file_path: str | Path) -> list[SecurityEvent]:
        path = Path(file_path)
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)

        if isinstance(data, dict) and "Records" in data:
            records = data["Records"]
        elif isinstance(data, list):
            records = data
        else:
            records = data.get("records", [])

        return self.ingest_records(records)

    def ingest_s3(
        self,
        bucket_name: str,
        prefix: str = "",
        max_files: int = 50,
    ) -> list[SecurityEvent]:
        """Fetch and normalize new CloudTrail log files from an S3 bucket.

        Each call sees the bucket afresh; deduplication is the caller's
        responsibility (the orchestrator stores events by id).
        """
        events: list[SecurityEvent] = []
        try:
            paginator = self.s3.get_paginator("list_objects_v2")
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                Prefix=prefix,
                PaginationConfig={"MaxItems": max_files},
            )

            processed = 0
            for page in page_iterator:
                for obj in page.get("Contents", []):
                    key = obj.get("Key", "")
                    if not key or processed >= max_files:
                        continue
                    if not (key.endswith(".json") or key.endswith(".json.gz") or key.endswith(".gz")):
                        continue

                    events.extend(self._read_s3_log_object(bucket_name, key))
                    processed += 1
                    if processed >= max_files:
                        break
        except (BotoCoreError, ClientError) as err:
            logger.error("Failed to list/fetch S3 logs from %s: %s", bucket_name, err)
        return events

    def ingest_live_lookup(
        self,
        max_results: int = 50,
        start_time: datetime | None = None,
        region_name: str = "us-east-1",
    ) -> list[SecurityEvent]:
        """Call CloudTrail lookup_events and normalize the results."""
        kwargs: dict[str, Any] = {"MaxResults": min(max_results, 50)}
        if start_time is not None:
            kwargs["StartTime"] = start_time

        try:
            response = self.cloudtrail.lookup_events(**kwargs)
        except (BotoCoreError, ClientError) as err:
            logger.error("CloudTrail lookup_events failed: %s", err)
            return []

        records: list[dict[str, Any]] = []
        for ct_event in response.get("Events", []):
            raw_json_str = ct_event.get("CloudTrailEvent", "{}")
            try:
                records.append(json.loads(raw_json_str))
            except json.JSONDecodeError:
                continue

        return self.ingest_records(records)

    # ---- Internals ----------------------------------------------------------

    def _read_s3_log_object(self, bucket: str, key: str) -> list[SecurityEvent]:
        try:
            response = self.s3.get_object(Bucket=bucket, Key=key)
            body_bytes = response["Body"].read()
        except (BotoCoreError, ClientError) as err:
            logger.warning("Failed to read s3://%s/%s: %s", bucket, key, err)
            return []

        try:
            if key.endswith(".gz"):
                with gzip.GzipFile(fileobj=io.BytesIO(body_bytes), mode="rb") as gz:
                    content = gz.read().decode("utf-8")
            else:
                content = body_bytes.decode("utf-8")
            data = json.loads(content)
        except (gzip.BadGzipFile, json.JSONDecodeError, UnicodeDecodeError) as err:
            logger.warning("Failed to parse s3://%s/%s: %s", bucket, key, err)
            return []

        records = data.get("Records", data.get("records", [])) if isinstance(data, dict) else data

        return self.ingest_records(records)

    def _parse_record(self, record: dict[str, Any]) -> SecurityEvent | None:
        try:
            event_time = datetime.fromisoformat(
                record["eventTime"].replace("Z", "+00:00")
            )
        except (KeyError, ValueError):
            return None

        event_source = record.get("eventSource", "")
        service = event_source.split(".")[0] if "." in event_source else event_source

        source = EventSource(
            provider="aws",
            service=service,
            collector="cloudtrail",
            event_type=record.get("eventType", "AwsApiCall"),
            event_name=record.get("eventName", ""),
            source_event_id=record.get("eventID"),
        )

        identity = record.get("userIdentity", {})
        actor = Actor(
            type=identity.get("type", "Unknown"),
            user_id=identity.get("principalId"),
            username=identity.get("userName"),
            arn=identity.get("arn"),
            account_id=identity.get("accountId") or record.get("awsAccountId"),
            access_key_id=identity.get("accessKeyId"),
        )

        source_network = SourceNetwork(
            ip=record.get("sourceIPAddress"),
            user_agent=record.get("userAgent"),
        )

        action = Action(
            category=self._categorize_action(record.get("eventName", "")),
            operation=record.get("eventName", ""),
            read_only=bool(record.get("readOnly", False)),
        )

        resource = self._extract_resource(record)

        error_code = record.get("errorCode")
        error_message = record.get("errorMessage")
        if error_code:
            status = "FAILURE"
        elif error_message == "Access Denied":
            status = "DENIED"
        else:
            status = "SUCCESS"

        result = EventResult(status=status, error_code=error_code, error_message=error_message)

        severity = self._determine_severity(record)

        return SecurityEvent(
            event_id=record.get("eventID", ""),
            event_time=event_time,
            source=source,
            actor=actor,
            source_network=source_network,
            action=action,
            resource=resource,
            result=result,
            severity=severity,
            metadata=record,
        )

    @staticmethod
    def _categorize_action(event_name: str) -> str:
        lower = event_name.lower()
        if any(x in lower for x in ("login", "authenticate", "assume")):
            return "authentication"
        if any(x in lower for x in ("create", "put", "attach", "add")):
            return "configuration"
        if any(x in lower for x in ("delete", "remove", "destroy")):
            return "deletion"
        if any(x in lower for x in ("get", "list", "describe", "view", "head")):
            return "read"
        if any(x in lower for x in ("update", "modify", "change")):
            return "modification"
        if any(x in lower for x in ("signout", "logout")):
            return "session"
        return "other"

    @staticmethod
    def _infer_resource_type(event_name: str) -> str:
        lower = event_name.lower()
        if "user" in lower:
            return "IAMUser"
        if "role" in lower:
            return "IAMRole"
        if "policy" in lower:
            return "IAMPolicy"
        if "bucket" in lower or "s3" in lower:
            return "S3Bucket"
        if "key" in lower:
            return "IAMAccessKey"
        if "table" in lower:
            return "DynamoDBTable"
        if "function" in lower or "lambda" in lower:
            return "LambdaFunction"
        if "cluster" in lower:
            return "ElasticsearchDomain"
        return "Unknown"

    @staticmethod
    def _extract_resource(record: dict[str, Any]) -> Resource:
        params = record.get("requestParameters") or {}
        resources = record.get("resources") or params.get("resources")
        if isinstance(resources, list) and resources:
            first = resources[0]
            if isinstance(first, dict):
                return Resource(
                    type=first.get("type", "Unknown"),
                    arn=first.get("arn"),
                    account_id=first.get("accountId"),
                    region=first.get("region"),
                    name=first.get("name") or params.get("resourceName"),
                )
            return Resource(type="Unknown", arn=str(first))

        return Resource(
            type=LocalIngestion._infer_resource_type(record.get("eventName", "")),
            arn=params.get("resourceArn") or params.get("bucketName") or params.get("roleName"),
            region=record.get("awsRegion"),
            name=params.get("resourceName") or params.get("bucketName") or params.get("userName"),
        )

    @staticmethod
    def _determine_severity(record: dict[str, Any]) -> str:
        event_name = record.get("eventName", "")
        error_code = record.get("errorCode", "")

        high_risk = {
            "AttachUserPolicy",
            "AttachRolePolicy",
            "AttachGroupPolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "PutGroupPolicy",
            "CreateAccessKey",
            "UpdateAccessKey",
            "CreateRole",
            "UpdateAssumeRolePolicy",
            "PutBucketPolicy",
            "DeleteBucketPolicy",
        }
        if event_name in high_risk:
            return "HIGH"
        if any(x in event_name.lower() for x in ("delete", "destroy")):
            return "MEDIUM"
        if error_code == "AccessDenied":
            return "MEDIUM"
        return "LOW"


class CloudTrailListenerManager:
    """Unified manager for the S3 and live-lookup ingestion paths.

    Used by `SecurityTower.run_monitoring_cycle` to pull telemetry from
    multiple sources and feed it into the analyzer pipeline.
    """

    def __init__(
        self,
        ingestion: LocalIngestion | None = None,
        boto3_session: Any | None = None,
    ) -> None:
        self.ingestion = ingestion or LocalIngestion(boto3_session=boto3_session)
        self._seen_object_keys: set[tuple[str, str]] = set()
        self._seen_event_ids: set[str] = set()

    def discover_cloudtrail_buckets(self) -> list[tuple[str, str]]:
        try:
            trails = self.ingestion.cloudtrail.describe_trails().get("trailList", [])
        except (BotoCoreError, ClientError) as err:
            logger.warning("CloudTrail trail auto-discovery failed: %s", err)
            return []
        return [
            (trail["S3BucketName"], trail.get("S3KeyPrefix", ""))
            for trail in trails
            if trail.get("S3BucketName")
        ]

    def poll_all(
        self,
        s3_bucket: str | None = None,
        s3_prefix: str = "",
        use_live_api: bool = True,
        auto_discover: bool = False,
        max_results: int = 50,
    ) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []

        target_buckets: list[tuple[str, str]] = []
        if s3_bucket:
            target_buckets.append((s3_bucket, s3_prefix))
        if auto_discover or not s3_bucket:
            for bucket, prefix in self.discover_cloudtrail_buckets():
                if (bucket, prefix) not in target_buckets:
                    target_buckets.append((bucket, prefix))

        for bucket, prefix in target_buckets:
            bucket_events = self.ingestion.ingest_s3(
                bucket_name=bucket, prefix=prefix, max_files=max_results
            )
            # Deduplicate by (bucket, key) at the file level is hard without
            # re-listing; per-event dedup is handled by the orchestrator via
            # the in-memory repo key.
            events.extend(bucket_events)

        if use_live_api:
            api_events = self.ingestion.ingest_live_lookup(max_results=max_results)
            for event in api_events:
                if event.event_id and event.event_id in self._seen_event_ids:
                    continue
                if event.event_id:
                    self._seen_event_ids.add(event.event_id)
                events.append(event)

        return events
