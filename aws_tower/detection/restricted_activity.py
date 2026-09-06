"""Detector for security-sensitive AWS operations."""

from __future__ import annotations

from ..events.models import SecurityEvent
from .base import Detector
from .models import DetectionFinding

RESTRICTED_OPERATIONS = {
    # IAM
    "DeleteUser",
    "DeleteRole",
    "PutUserPolicy",
    "PutRolePolicy",
    "AttachUserPolicy",
    "AttachGroupPolicy",
    "AttachRolePolicy",

    # S3
    "DeleteObject",
    "DeleteBucket",
    "PutBucketPolicy",
}


class RestrictedActivityDetector(Detector):
    """Detect security-sensitive AWS operations."""

    name = "restricted_activity"

    def detect(
        self,
        event: SecurityEvent,
    ) -> DetectionFinding | None:

        operation = event.action.operation

        if operation not in RESTRICTED_OPERATIONS:
            return None

        return DetectionFinding(
            detector=self.name,
            title="Restricted activity detected",
            description=(
                f"Security-sensitive operation "
                f"'{operation}' was performed."
            ),
            severity="HIGH",
            event_id=event.event_id,
            actor_id=(
                event.actor.arn
                or event.actor.user_id
                or event.actor.username
            ),
            resource_id=(
                event.resource.arn
                or event.resource.name
            ),
            evidence={
                "operation": operation,
                "category": event.action.category,
                "source_ip": event.source_network.ip,
                "result": event.result.status,
            },
        )
