"""Local remediation plan templates.

Given an incident type and a details dict, return a structured plan that the
orchestrator (or a human) can review and execute. No LLM is involved; templates
are pure data + a thin assembly layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Each template produces a list of action steps. An action step is a dict with
# an `action` (matching a method in `RemediationActions`), `parameters`, and a
# human-readable `description`. `auto_executable` controls whether the step
# runs without human confirmation; `requires_confirmation` marks steps that
# must be reviewed before running.
_TEMPLATES: dict[str, dict[str, Any]] = {
    "compromised_credential": {
        "summary": "Deactivate the affected user's access keys and recommend blocking the source IP.",
        "required_fields": ["actor", "key_id"],
        "optional_fields": ["ip"],
        "steps": [
            {
                "action": "deactivate_key",
                "parameters": {"user_name": "{actor}", "access_key_id": "{key_id}"},
                "description": "Deactivate all access keys for the affected IAM user.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
            {
                "action": "block_ip",
                "parameters": {"ip_address": "{ip}", "reason": "Compromised credential activity"},
                "description": "Recommend WAF / SG / NACL deny rules for the source IP.",
                "auto_executable": False,
                "requires_confirmation": False,
            },
        ],
    },
    "excessive_permissions": {
        "summary": "Detach broad managed policies and request a policy review.",
        "required_fields": ["actor", "policy_arn"],
        "optional_fields": [],
        "steps": [
            {
                "action": "detach_user_policy",
                "parameters": {"user_name": "{actor}", "policy_arn": "{policy_arn}"},
                "description": "Detach the overly permissive managed policy from the user.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
        ],
    },
    "s3_public_access": {
        "summary": "Lock down the affected bucket with a Deny statement and full public-access block.",
        "required_fields": ["bucket"],
        "optional_fields": [],
        "steps": [
            {
                "action": "update_bucket_policy",
                "parameters": {
                    "bucket_name": "{bucket}",
                    "effect": "Deny",
                    "principal": "*",
                },
                "description": "Append a Deny statement to the bucket policy.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
            {
                "action": "enable_public_access_block",
                "parameters": {"bucket_name": "{bucket}"},
                "description": "Enable all four S3 public-access-block flags.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
        ],
    },
    "privilege_escalation": {
        "summary": "Detach the policy that was just attached and add detection coverage.",
        "required_fields": ["actor", "policy_arn"],
        "optional_fields": ["key_id"],
        "steps": [
            {
                "action": "detach_user_policy",
                "parameters": {"user_name": "{actor}", "policy_arn": "{policy_arn}"},
                "description": "Detach the sensitive policy that was just attached.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
            {
                "action": "deactivate_key",
                "parameters": {"user_name": "{actor}", "access_key_id": "{key_id}"},
                "description": "Deactivate the access key used during escalation.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
        ],
    },
    "unauthorized_activity": {
        "summary": "Deactivate the user's keys and log an advisory.",
        "required_fields": ["actor"],
        "optional_fields": ["key_id", "ip"],
        "steps": [
            {
                "action": "deactivate_key",
                "parameters": {"user_name": "{actor}", "access_key_id": "{key_id}"},
                "description": "Deactivate access keys for the user.",
                "auto_executable": True,
                "requires_confirmation": True,
            },
            {
                "action": "block_ip",
                "parameters": {"ip_address": "{ip}", "reason": "Unauthorized activity"},
                "description": "Recommend IP block for the source address.",
                "auto_executable": False,
                "requires_confirmation": False,
            },
        ],
    },
}


class LocalRemediationPlanner:
    """Produce remediation plans from deterministic templates."""

    def generate_plan(
        self,
        incident_type: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        details = details or {}
        template = _TEMPLATES.get(incident_type)
        if not template:
            return {
                "error": f"Unknown incident type: {incident_type}",
                "available_types": list(_TEMPLATES.keys()),
            }

        required_fields = template.get("required_fields", [])
        missing_fields = [f for f in required_fields if f not in details]
        if missing_fields:
            return {
                "error": f"Missing required fields: {', '.join(missing_fields)}",
                "required_fields": required_fields,
                "provided_fields": list(details.keys()),
            }

        steps = [
            self._render_step(step_template, details)
            for step_template in template["steps"]
        ]

        return {
            "incident_type": incident_type,
            "summary": template["summary"],
            "steps": steps,
            "auto_executable": any(step["auto_executable"] for step in steps),
            "requires_confirmation": any(step["requires_confirmation"] for step in steps),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "source": "local-template",
        }

    def execute_plan(self, plan: dict[str, Any], actions: Any) -> dict[str, Any]:
        """Execute a plan's steps via the provided RemediationActions instance."""
        results: list[dict[str, Any]] = []
        steps = plan.get("steps", [])

        for step in steps:
            if step.get("requires_confirmation") and not plan.get("force", False):
                results.append(
                    {
                        "action": step.get("action"),
                        "status": "SKIPPED",
                        "reason": "requires_confirmation",
                    }
                )
                continue

            try:
                outcome = actions.execute(step.get("action"), step.get("parameters", {}))
                results.append(
                    {
                        "action": step.get("action"),
                        "status": "SUCCESS" if "error" not in outcome else "FAILED",
                        "result": outcome,
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "action": step.get("action"),
                        "status": "FAILED",
                        "error": str(exc),
                    }
                )

        return {
            "remediation_id": f"rem-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "executed_at": datetime.now(timezone.utc).isoformat(),
            "status": (
                "COMPLETED"
                if all(r["status"] in {"SUCCESS", "SKIPPED"} for r in results)
                else "PARTIAL"
            ),
            "results": results,
        }

    @staticmethod
    def _render_step(template: dict[str, Any], details: dict[str, Any]) -> dict[str, Any]:
        rendered_params: dict[str, Any] = {}
        for key, value in template.get("parameters", {}).items():
            if isinstance(value, str) and "{" in value:
                # Use format_map with a Mapping that defers to details.
                # We want unfilled placeholders to stay as the original
                # `{key}` token so the operator can see what's missing.
                # A plain defaultdict(str) would substitute "" for
                # missing keys; instead we use a dict subclass whose
                # __missing__ returns the original `{name}` token.
                try:
                    rendered_params[key] = value.format_map(_SafeFormatMap(details))
                except (KeyError, IndexError):
                    rendered_params[key] = value
            else:
                rendered_params[key] = value

        return {
            "action": template["action"],
            "parameters": rendered_params,
            "description": template["description"],
            "auto_executable": template["auto_executable"],
            "requires_confirmation": template["requires_confirmation"],
        }


class _SafeFormatMap(dict):
    """A dict that maps missing keys to their original `{name}` token.

    Used as a `format_map` argument so template strings with unfilled
    placeholders render unchanged instead of raising KeyError or
    substituting empty strings.
    """

    def __missing__(self, key: str) -> str:  # type: ignore[override]
        return "{" + key + "}"
