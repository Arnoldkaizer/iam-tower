"""Tests for the CLI command definitions."""

import unittest

from aws_tower.tower.cli import IncidentType


class TestIncidentTypeEnum(unittest.TestCase):
    def test_all_five_templates_are_listed(self):
        values = {it.value for it in IncidentType}
        self.assertEqual(
            values,
            {
                "compromised_credential",
                "privilege_escalation",
                "s3_public_access",
                "excessive_permissions",
                "unauthorized_activity",
            },
        )

    def test_enum_is_string_compatible(self):
        # IncidentType inherits from str so it can be passed to Typer
        # options and to functions expecting a string.
        for it in IncidentType:
            self.assertIsInstance(it, str)
            self.assertEqual(it, it.value)

    def test_unknown_value_raises(self):
        with self.assertRaises(ValueError):
            IncidentType("not_a_real_type")


if __name__ == "__main__":
    unittest.main()
