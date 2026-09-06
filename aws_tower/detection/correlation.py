"""Risk correlation engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..risk import clamp_risk_score, score_to_risk_level
from .models import DetectionFinding

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
    "CRITICAL": 10,
}


@dataclass
class CorrelationResult:
    score: float
    risk_level: str
    findings: list[DetectionFinding] = field(default_factory=list)


def apply_correlation_rules(
    findings: list[DetectionFinding],
    score: float,
) -> float:
    """Increase risk when multiple security signals coexist."""

    detector_names = {
        finding.detector
        for finding in findings
    }

    if {
        "restricted_activity",
        "out_of_company_ip",
        "irregular_hour",
    }.issubset(detector_names):
        return min(
            round(score * 1.5, 1),
            10.0,
        )

    if {
        "restricted_activity",
        "out_of_company_ip",
    }.issubset(detector_names):
        return min(
            round(score * 1.25, 1),
            10.0,
        )

    return score


class RiskCorrelator:
    """Combine detector findings into an aggregate risk assessment."""

    def correlate(
        self,
        findings: list[DetectionFinding],
    ) -> CorrelationResult:

        if not findings:
            return CorrelationResult(
                score=0.0,
                risk_level="LOW",
                findings=[],
            )

        total_weight = sum(
            SEVERITY_WEIGHTS.get(
                finding.severity,
                0,
            )
            for finding in findings
        )

        max_weight = len(findings) * 10

        score = 0.0 if max_weight == 0 else round(total_weight / max_weight * 10, 1)

        score = apply_correlation_rules(
            findings,
            score,
        )
        score = clamp_risk_score(score)

        risk_level = score_to_risk_level(score)

        return CorrelationResult(
            score=score,
            risk_level=risk_level,
            findings=list(findings),
        )
