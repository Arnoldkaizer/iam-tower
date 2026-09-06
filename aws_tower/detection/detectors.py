"""Default detector registry builder."""

from __future__ import annotations

from .ip_anomaly import OutOfCompanyIPDetector
from .registry import DetectorRegistry
from .restricted_activity import RestrictedActivityDetector
from .time_anomaly import IrregularHourDetector


def build_default_registry(
    trusted_networks: list[str],
    *,
    business_start_hour: int = 8,
    business_end_hour: int = 18,
) -> DetectorRegistry:
    """Build the default event-level security detector registry."""

    registry = DetectorRegistry(
        [
            RestrictedActivityDetector(),
            OutOfCompanyIPDetector(
                trusted_networks
            ),
            IrregularHourDetector(
                start_hour=business_start_hour,
                end_hour=business_end_hour,
            ),
        ]
    )

    return registry
