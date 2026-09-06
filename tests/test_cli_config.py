"""Tests for the persistent CLI configuration."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aws_tower.tower import config as tower_config


class TestLoadConfig(unittest.TestCase):
    def test_missing_file_returns_defaults(self):
        with tempfile.TemporaryDirectory() as d, patch.object(
            tower_config, "config_path", lambda cwd=None: Path(d) / ".aws_tower.json"
        ):
            cfg = tower_config.load_config()
        self.assertEqual(cfg["trusted_networks"], [])
        self.assertEqual(cfg["business_start_hour"], 8)
        self.assertEqual(cfg["business_end_hour"], 18)
        self.assertEqual(cfg["access_denied_window_minutes"], 10)
        self.assertEqual(cfg["access_denied_threshold"], 5)

    def test_partial_file_is_merged_with_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".aws_tower.json"
            path.write_text(json.dumps({"trusted_networks": ["10.0.0.0/8"]}), encoding="utf-8")
            with patch.object(tower_config, "config_path", lambda cwd=None: path):
                cfg = tower_config.load_config()
        # Override was applied
        self.assertEqual(cfg["trusted_networks"], ["10.0.0.0/8"])
        # Defaults were filled in for missing keys
        self.assertEqual(cfg["business_start_hour"], 8)
        self.assertEqual(cfg["min_risk_score"], 4.0)

    def test_malformed_file_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".aws_tower.json"
            path.write_text("not valid json {", encoding="utf-8")
            with patch.object(tower_config, "config_path", lambda cwd=None: path):
                cfg = tower_config.load_config()
        self.assertEqual(cfg["trusted_networks"], [])
        self.assertEqual(cfg["business_start_hour"], 8)

    def test_non_object_root_falls_back_to_defaults(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".aws_tower.json"
            path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
            with patch.object(tower_config, "config_path", lambda cwd=None: path):
                cfg = tower_config.load_config()
        self.assertEqual(cfg, dict(tower_config.DEFAULTS))


class TestSaveConfig(unittest.TestCase):
    def test_save_merges_with_existing(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".aws_tower.json"
            path.write_text(json.dumps({"trusted_networks": ["10.0.0.0/8"]}), encoding="utf-8")
            with patch.object(tower_config, "config_path", lambda cwd=None: path):
                tower_config.save_config({"business_start_hour": 7})
            # Read back directly from disk so the mock isn't needed.
            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["business_start_hour"], 7)
            # Existing value preserved
            self.assertEqual(written["trusted_networks"], ["10.0.0.0/8"])

    def test_save_creates_file_if_missing(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".aws_tower.json"
            self.assertFalse(path.exists())
            with patch.object(tower_config, "config_path", lambda cwd=None: path):
                tower_config.save_config({"business_start_hour": 9})
            self.assertTrue(path.exists())
            written = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(written["business_start_hour"], 9)

    def test_save_returns_the_path(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / ".aws_tower.json"
            with patch.object(tower_config, "config_path", lambda cwd=None: path):
                returned = tower_config.save_config({"min_risk_score": 6.5})
            self.assertEqual(returned, path)


if __name__ == "__main__":
    unittest.main()
