"""In-memory assessment repository implementation."""

from __future__ import annotations

from datetime import datetime

from ..detection.correlation import CorrelationResult
from .models import SecurityAssessment
from .repository import AssessmentRepository


class InMemoryAssessmentRepository(AssessmentRepository):
    """In-memory implementation of AssessmentRepository."""

    def __init__(self) -> None:
        self._assessments: dict[str, SecurityAssessment] = {}

    def save(
        self,
        assessment: SecurityAssessment | None = None,
        *,
        assessment_id: str | None = None,
        actor_id: str | None = None,
        assessed_at: datetime | None = None,
        result: CorrelationResult | None = None,
    ) -> None:
        if assessment is not None:
            self._assessments[assessment.assessment_id] = assessment
        elif (
            assessment_id is not None
            and actor_id is not None
            and assessed_at is not None
            and result is not None
        ):
            obj = SecurityAssessment.from_result(
                assessment_id=assessment_id,
                actor_id=actor_id,
                assessed_at=assessed_at,
                result=result,
            )
            self._assessments[obj.assessment_id] = obj
        else:
            raise ValueError("Either assessment object or kwargs must be provided")

    def get(
        self,
        *,
        assessment_id: str,
    ) -> SecurityAssessment | None:
        return self._assessments.get(assessment_id)

    def query_by_actor(
        self,
        *,
        actor_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityAssessment]:
        results = []

        for assessment in self._assessments.values():
            if assessment.actor_id != actor_id:
                continue

            if start_time is not None and assessment.assessed_at < start_time:
                continue

            if end_time is not None and assessment.assessed_at > end_time:
                continue

            results.append(assessment)

        results.sort(key=lambda assessment: assessment.assessed_at)

        return results

    def get_latest_by_actor(self, actor_id: str) -> SecurityAssessment | None:
        actor_assessments = self.query_by_actor(actor_id=actor_id)
        if not actor_assessments:
            return None
        return actor_assessments[-1]

    def list_latest(self, limit: int = 10) -> list[SecurityAssessment]:
        latest_by_actor: dict[str, SecurityAssessment] = {}
        for a in sorted(self._assessments.values(), key=lambda x: x.assessed_at):
            latest_by_actor[a.actor_id] = a
        return sorted(latest_by_actor.values(), key=lambda x: x.assessed_at, reverse=True)[:limit]
