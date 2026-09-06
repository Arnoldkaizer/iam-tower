"""Security Tower orchestrator (local, rule-based).

The orchestrator composes the local analyzer, posture analyzer, and
remediation planner into the same public surface the CLI and tests expect.
All analysis is deterministic and runs in-process; no external AI service
is required.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3

from ..alerting import AlertManager, ConsoleAlertSink
from ..analyzer.local_analyzer import LocalAnalyzer
from ..assessment.in_memory import InMemoryAssessmentRepository
from ..assessment.models import SecurityAssessment
from ..assessment.repository import AssessmentRepository
from ..assessment.sqlite import SQLiteAssessmentRepository
from ..events.in_memory import InMemoryEventRepository
from ..events.models import SecurityEvent
from ..events.repository import EventRepository
from ..events.sqlite import SQLiteEventRepository
from ..posture.local_posture import LocalPostureAnalyzer
from ..remediation.actions import RemediationActions
from ..remediation.planner import LocalRemediationPlanner
from ..risk import clamp_risk_score
from .ingestion import CloudTrailListenerManager, LocalIngestion
from .investigation import InvestigationEngine


class SecurityTower:
    """Security Tower with local, rule-based analysis and remediation.

    Composes:
    - LocalIngestion / CloudTrailListenerManager for telemetry
    - LocalAnalyzer for per-actor and bulk event analysis
    - LocalPostureAnalyzer for AWS account posture
    - LocalRemediationPlanner + RemediationActions for plan generation/execution
    """

    def __init__(
        self,
        *,
        event_repository: EventRepository | None = None,
        assessment_repository: AssessmentRepository | None = None,
        repository_path: str | Path | None = None,
        alert_manager: AlertManager | None = None,
        ingestion: LocalIngestion | None = None,
        listener_manager: CloudTrailListenerManager | None = None,
        analyzer: LocalAnalyzer | None = None,
        posture_analyzer: LocalPostureAnalyzer | None = None,
        planner: LocalRemediationPlanner | None = None,
        actions: RemediationActions | None = None,
        boto3_session: Any | None = None,
        trusted_networks: list[str] | None = None,
        business_start_hour: int = 8,
        business_end_hour: int = 18,
    ) -> None:
        if repository_path is not None and (event_repository or assessment_repository):
            raise ValueError("repository_path cannot be combined with repository instances")
        self.event_repo = event_repository or (
            SQLiteEventRepository(repository_path)
            if repository_path is not None
            else InMemoryEventRepository()
        )
        self.assessment_repo = assessment_repository or (
            SQLiteAssessmentRepository(repository_path)
            if repository_path is not None
            else InMemoryAssessmentRepository()
        )
        self.alert_manager = alert_manager or AlertManager(sinks=[ConsoleAlertSink()])

        session = boto3_session or boto3.Session()
        self.ingestion = ingestion or LocalIngestion(boto3_session=session)
        self._listener_manager = listener_manager
        self.analyzer = analyzer or LocalAnalyzer(
            trusted_networks=trusted_networks or [],
            business_start_hour=business_start_hour,
            business_end_hour=business_end_hour,
        )
        self.posture_analyzer = posture_analyzer or LocalPostureAnalyzer(
            boto3_session=session
        )
        self.planner = planner or LocalRemediationPlanner()
        self.actions = actions or RemediationActions(boto3_session=session)

        self.investigation = InvestigationEngine(
            event_repository=self.event_repo,
            assessment_repository=self.assessment_repo,
            analyzer=self.analyzer,
        )

    # ---- Ingestion ---------------------------------------------------------

    def ingest_events(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Save already-normalized security events to the repository."""
        for event in events:
            self.event_repo.save(event)
        return events

    def ingest_records(self, records: list[dict[str, Any]]) -> list[SecurityEvent]:
        """Parse raw CloudTrail records and save them."""
        return self.ingest_events(self.ingestion.ingest_records(records))

    def ingest_file(self, file_path: str) -> list[SecurityEvent]:
        """Read events from a CloudTrail JSON/Gzip file and save them."""
        return self.ingest_events(self.ingestion.ingest_file(file_path))

    def ingest_s3(
        self, bucket_name: str, prefix: str = "", max_files: int = 50
    ) -> list[SecurityEvent]:
        """Fetch CloudTrail log files from an S3 bucket and save them."""
        return self.ingest_events(
            self.ingestion.ingest_s3(
                bucket_name=bucket_name, prefix=prefix, max_files=max_files
            )
        )

    def ingest_live_lookup(
        self,
        start_time: datetime | None = None,
        max_results: int = 50,
        region_name: str = "us-east-1",
    ) -> list[SecurityEvent]:
        """Fetch live CloudTrail events via lookup_events and save them."""
        return self.ingest_events(
            self.ingestion.ingest_live_lookup(
                max_results=max_results, start_time=start_time, region_name=region_name
            )
        )

    def run_monitoring_cycle(
        self,
        use_live_cloudtrail: bool = True,
        s3_bucket: str | None = None,
        s3_prefix: str = "",
        auto_discover: bool = False,
        dispatch_alerts: bool = True,
    ) -> tuple[list[SecurityEvent], list[SecurityAssessment]]:
        """Run a single real-time monitoring and threat assessment cycle."""
        if self._listener_manager is None:
            self._listener_manager = CloudTrailListenerManager(ingestion=self.ingestion)

        events = self._listener_manager.poll_all(
            s3_bucket=s3_bucket,
            s3_prefix=s3_prefix,
            use_live_api=use_live_cloudtrail,
            auto_discover=auto_discover,
        )
        self.ingest_events(events)
        assessments = self.assess_all_actors(dispatch_alerts=dispatch_alerts)
        return events, assessments

    # ---- Analysis ----------------------------------------------------------

    def assess_all_actors(self, *, dispatch_alerts: bool = True) -> list[SecurityAssessment]:
        """Run the local analyzer against every actor in the event repo."""
        actors = self.event_repo.list_all_actors()
        all_events = self.event_repo.query_by_time_range()
        assessments: list[SecurityAssessment] = []

        for actor in actors:
            actor_events = self.event_repo.query_by_actor(actor_id=actor)
            if not actor_events:
                continue

            analysis = self.analyzer.analyze_actor_behavior(actor, all_events)
            risk_score = clamp_risk_score(analysis.get("risk_score", 0.0))
            risk_level = analysis.get("risk_level", "LOW")

            assessment = SecurityAssessment(
                assessment_id=str(uuid.uuid4()),
                actor_id=actor,
                assessed_at=datetime.now(timezone.utc),
                score=risk_score,
                risk_level=risk_level,
                findings=analysis.get("findings", []),
            )
            self.assessment_repo.save(assessment)

            if dispatch_alerts and self.alert_manager:
                self.alert_manager.process_assessment(assessment)

            assessments.append(assessment)

        return assessments

    def analyze_events(self, events: list[SecurityEvent]) -> dict[str, Any]:
        """Analyze events using the local rule-based pipeline."""
        return self.analyzer.analyze_events(events)

    def analyze_actor(
        self, actor_id: str, events: list[SecurityEvent]
    ) -> dict[str, Any]:
        """Analyze behavior of a specific actor."""
        return self.analyzer.analyze_actor_behavior(actor_id, events)

    def detect_threats(self, events: list[SecurityEvent]) -> list[dict[str, Any]]:
        """Detect specific threats from events."""
        return self.analyzer.detect_threats(events)

    # ---- Posture -----------------------------------------------------------

    def assess_posture(self) -> dict[str, Any]:
        """Run the local posture analyzer against the AWS account."""
        return self.posture_analyzer.analyze_posture()

    # ---- Remediation -------------------------------------------------------

    def generate_remediation_plan(
        self, incident_type: str, details: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate a remediation plan from local templates."""
        return self.planner.generate_plan(incident_type, details)

    def execute_remediation(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Execute a remediation plan via the local action executor."""
        return self.planner.execute_plan(plan, self.actions)

    def auto_remediate(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Build and execute a plan for a known incident type."""
        incident_type = incident.get("type", "unauthorized_activity")
        details = incident.get("details", {})
        plan = self.planner.generate_plan(incident_type, details)
        plan["force"] = bool(incident.get("force", False))
        return self.planner.execute_plan(plan, self.actions)

    # ---- Full pipeline -----------------------------------------------------

    def run_full_analysis(self, events: list[SecurityEvent]) -> dict[str, Any]:
        """Run complete analysis pipeline: ingest, analyze, posture, plan."""
        self.ingest_events(events)
        event_analysis = self.analyze_events(events)
        posture_analysis = self.assess_posture()

        threats = event_analysis.get("threats", [])
        remediation_plan = self.generate_remediation_plan(
            incident_type="comprehensive_analysis",
            details={
                "threats": threats,
                "posture_issues": posture_analysis.get("summary", ""),
                "overall_risk": posture_analysis.get("overall_risk_score", {}),
            },
        )

        return {
            "event_analysis": event_analysis,
            "posture_analysis": posture_analysis,
            "remediation_plan": remediation_plan,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def process_and_assess(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        """Process records, analyze, and generate assessments."""
        events = self.ingest_records(records)
        if not events:
            return {"status": "empty", "message": "No events to process"}
        return {
            "status": "completed",
            "events_processed": len(events),
            "analysis": self.run_full_analysis(events),
        }
