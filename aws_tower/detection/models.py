"""Detection findings and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectionFinding:
    detector: str
    title: str
    description: str
    severity: str

    event_id: str

    actor_id: str | None = None
    resource_id: str | None = None

    evidence: dict[str, Any] = field(
        default_factory=dict
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )
