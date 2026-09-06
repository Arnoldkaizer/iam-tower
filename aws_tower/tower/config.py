"""Persistent configuration for the CLI.

Settings (trusted networks, business hours, alert thresholds) are read
from a small JSON file in the user's working directory. The file is
created on first write and updated in place. If the file is missing or
malformed, defaults are returned silently — the CLI stays usable even
when no config has been set.

The config file is intentionally limited to non-secret values. AWS
credentials are not stored here; they come from the standard boto3
credential chain.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CONFIG_FILENAME = ".aws_tower.json"
DATABASE_FILENAME = ".aws_tower.db"


DEFAULTS: dict[str, Any] = {
    "trusted_networks": [],
    "business_start_hour": 8,
    "business_end_hour": 18,
    "access_denied_window_minutes": 10,
    "access_denied_threshold": 5,
    "min_risk_score": 4.0,
}


def config_path(cwd: Path | None = None) -> Path:
    """Return the path to the config file under the given directory."""
    return (cwd or Path.cwd()) / CONFIG_FILENAME


def database_path(cwd: Path | None = None) -> Path:
    """Return the SQLite database path used for event and assessment history."""
    return (cwd or Path.cwd()) / DATABASE_FILENAME


def load_config(cwd: Path | None = None) -> dict[str, Any]:
    """Load config from disk, falling back to defaults for any missing key.

    A missing file is not an error. A malformed file is logged and
    treated as empty so the user can recover by re-running the
    `configure` command.
    """
    path = config_path(cwd)
    if not path.exists():
        return dict(DEFAULTS)

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        logger.warning("Could not parse %s; using defaults: %s", path, exc)
        return dict(DEFAULTS)

    if not isinstance(raw, dict):
        logger.warning("Expected a JSON object in %s; using defaults", path)
        return dict(DEFAULTS)

    merged = dict(DEFAULTS)
    merged.update(raw)
    return merged


def save_config(values: dict[str, Any], cwd: Path | None = None) -> Path:
    """Persist the given values to the config file and return the path."""
    path = config_path(cwd)
    merged = load_config(cwd)
    merged.update(values)
    path.write_text(json.dumps(merged, indent=2, sort_keys=True), encoding="utf-8")
    return path
