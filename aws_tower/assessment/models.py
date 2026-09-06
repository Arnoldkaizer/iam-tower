"""Security assessment models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ..detection.correlation import CorrelationResult
from ..detection.models import DetectionFinding
from ..risk import clamp_risk_score


@dataclass(frozen=True)
class SecurityAssessment:
    """A persisted security assessment for an actor."""

    assessment_id: str
    actor_id: str
    assessed_at: datetime
    score: float
    risk_level: str
    findings: list[DetectionFinding]

    def __post_init__(self) -> None:
        object.__setattr__(self, "score", clamp_risk_score(self.score))

    @property
    def risk_score(self) -> float:
        return self.score

    @classmethod
    def from_result(
        cls,
        *,
        assessment_id: str,
        actor_id: str,
        assessed_at: datetime,
        result: CorrelationResult,
    ) -> SecurityAssessment:
        return cls(
            assessment_id=assessment_id,
            actor_id=actor_id,
            assessed_at=assessed_at,
            score=result.score,
            risk_level=result.risk_level,
            findings=list(result.findings),
        )

    def to_result(self) -> CorrelationResult:
        return CorrelationResult(
            score=self.score,
            risk_level=self.risk_level,
            findings=list(self.findings),
        )
