"""Security event models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class EventSource:
    provider: str
    service: str
    collector: str
    event_type: str
    event_name: str
    source_event_id: str | None = None


@dataclass
class Actor:
    type: str
    user_id: str | None = None
    username: str | None = None
    arn: str | None = None
    account_id: str | None = None
    access_key_id: str | None = None
    session_id: str | None = None


@dataclass
class SourceNetwork:
    ip: str | None = None
    country: str | None = None
    region: str | None = None
    user_agent: str | None = None
    vpc_id: str | None = None


@dataclass
class Action:
    category: str
    operation: str
    read_only: bool


@dataclass
class Resource:
    type: str
    arn: str | None = None
    account_id: str | None = None
    region: str | None = None
    name: str | None = None
    parent: str | None = None

    # S3-specific information
    bucket: str | None = None
    object_key: str | None = None
    version_id: str | None = None
    size_bytes: int | None = None


@dataclass
class EventResult:
    status: str
    error_code: str | None = None
    error_message: str | None = None


@dataclass
class SecurityAnalysis:
    risk_score: float = 0.0
    risk_level: str = "LOW"
    detection_status: str = "UNANALYZED"


@dataclass
class SecurityEvent:
    event_id: str
    event_time: datetime

    source: EventSource
    actor: Actor
    source_network: SourceNetwork
    action: Action
    resource: Resource
    result: EventResult

    severity: str

    event_version: str = "1.0"
    ingested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    security: SecurityAnalysis = field(default_factory=SecurityAnalysis)

    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.event_id:
            raise ValueError("event_id is required")

        if self.event_time.tzinfo is None:
            raise ValueError("event_time must be timezone-aware")

        valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        if self.severity not in valid_severities:
            raise ValueError(f"Invalid severity: {self.severity}")

        valid_statuses = {
            "SUCCESS",
            "FAILURE",
            "DENIED",
            "UNKNOWN",
        }

        if self.result.status not in valid_statuses:
            raise ValueError(f"Invalid result status: {self.result.status}")
