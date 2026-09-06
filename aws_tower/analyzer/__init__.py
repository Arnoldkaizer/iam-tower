"""Local rule-based security analyzer."""

from .local_analyzer import (
    AccessDeniedSpikeDetector,
    ConsoleLoginWithoutMFADetector,
    LocalAnalyzer,
    RootAccountUsageDetector,
)

__all__ = [
    "AccessDeniedSpikeDetector",
    "ConsoleLoginWithoutMFADetector",
    "LocalAnalyzer",
    "RootAccountUsageDetector",
]
