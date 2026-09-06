"""Assessment repository interface."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from .models import SecurityAssessment


class AssessmentRepository(Protocol):
    """Interface for storing and retrieving actor security assessments.

    Both the in-memory and SQLite implementations conform to this
    protocol. The orchestrator depends only on this surface.
    """

    def save(self, assessment: SecurityAssessment) -> None:
        """Persist a single security assessment."""
        ...

    def get(self, *, assessment_id: str) -> SecurityAssessment | None:
        """Retrieve one assessment by its primary key."""
        ...

    def query_by_actor(
        self,
        *,
        actor_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[SecurityAssessment]:
        """Retrieve assessments for a single actor, time-filtered."""
        ...

    def get_latest_by_actor(self, actor_id: str) -> SecurityAssessment | None:
        """Return the most recent assessment for an actor, if any."""
        ...

    def list_latest(self, limit: int = 10) -> list[SecurityAssessment]:
        """Return the latest assessment per actor, newest first, capped at limit."""
        ...
