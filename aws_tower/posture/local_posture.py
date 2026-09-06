"""Local rule-based security posture analyzer.

Reads IAM policies, S3 bucket configs, access keys, and IAM user settings via
boto3 and applies a deterministic rule set. Output shape matches what the
orchestrator and CLI expect.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class PostureIssue:
    """A single rule violation surfaced by the posture analyzer."""

    resource: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    rule: str
    description: str
    recommendation: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --- Thresholds -------------------------------------------------------------

KEY_AGE_HIGH_DAYS = 90
KEY_AGE_CRITICAL_DAYS = 180
PASSWORD_AGE_MEDIUM_DAYS = 90
MIN_RECOMMENDED_PASSWORD_LENGTH = 14


# --- Analyzer ---------------------------------------------------------------


class LocalPostureAnalyzer:
    """Run deterministic posture checks against the AWS account."""

    def __init__(
        self,
        boto3_session: Any | None = None,
        iam_client: Any | None = None,
        s3_client: Any | None = None,
    ) -> None:
        self._session = boto3_session
        self._iam_client_override = iam_client
        self._s3_client_override = s3_client

    @property
    def session(self) -> Any:
        if self._session is None:
            self._session = boto3.Session()
        return self._session

    @property
    def iam_client(self) -> Any:
        if self._iam_client_override is not None:
            return self._iam_client_override
        return self.session.client("iam")

    @property
    def s3(self) -> Any:
        """Return the S3 client, creating one on first access."""
        if self._s3_client_override is not None:
            return self._s3_client_override
        if not hasattr(self, "_s3_client_cached") or self._s3_client_cached is None:
            self._s3_client_cached = self.session.client("s3")
        return self._s3_client_cached

    def analyze_posture(self) -> dict[str, Any]:
        """Run every check and return an aggregated report."""
        iam_issues = self._safe(self._check_iam_policies, [])
        bucket_issues = self._safe(self._check_bucket_policies, [])
        keys_issues = self._safe(self._check_access_keys, [])
        users_issues = self._safe(self._check_iam_users, [])

        iam_analysis = self._section(iam_issues, "IAM Policies")
        bucket_analysis = self._section(bucket_issues, "S3 Buckets")
        keys_analysis = self._section(keys_issues, "Access Keys")
        users_analysis = self._section(users_issues, "IAM Users")

        overall = self._overall([iam_analysis, bucket_analysis, keys_analysis, users_analysis])

        return {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "iam_analysis": iam_analysis,
            "bucket_analysis": bucket_analysis,
            "keys_analysis": keys_analysis,
            "users_analysis": users_analysis,
            "overall_risk_score": overall,
            "summary": self._summary(
                [iam_analysis, bucket_analysis, keys_analysis, users_analysis]
            ),
        }

    # --- IAM policies -------------------------------------------------------

    def _check_iam_policies(self) -> list[PostureIssue]:
        issues: list[PostureIssue] = []
        try:
            paginator = self.iam_client.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy.get("Arn")
                    policy_name = policy.get("PolicyName")
                    if not policy_arn:
                        continue

                    try:
                        versions = self.iam_client.list_policy_versions(PolicyArn=policy_arn)
                        default_version = next(
                            (
                                v
                                for v in versions.get("Versions", [])
                                if v.get("IsDefaultVersion")
                            ),
                            None,
                        )
                        if not default_version:
                            continue
                        version_id = default_version["VersionId"]
                        doc_response = self.iam_client.get_policy_version(
                            PolicyArn=policy_arn, VersionId=version_id
                        )
                        document = doc_response.get("PolicyVersion", {}).get("Document", {})
                    except ClientError as exc:
                        if self._is_access_denied(exc):
                            raise
                        continue

                    self._check_policy_document(
                        policy_arn=policy_arn,
                        policy_name=policy_name or "unknown",
                        document=document,
                        issues=issues,
                    )
        except ClientError:
            raise
        return issues

    @staticmethod
    def _check_policy_document(
        *,
        policy_arn: str,
        policy_name: str,
        document: dict[str, Any],
        issues: list[PostureIssue],
    ) -> None:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect")
            actions = statement.get("Action", [])
            resources = statement.get("Resource", [])
            condition = statement.get("Condition")

            if effect != "Allow":
                continue

            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]

            action_is_wildcard = "*" in actions
            resource_is_wildcard = "*" in resources
            iam_wildcard = any(a == "iam:*" or a == "*" for a in actions)

            if action_is_wildcard and resource_is_wildcard:
                issues.append(
                    PostureIssue(
                        resource=policy_arn,
                        severity="CRITICAL",
                        rule="iam_policy_admin_wildcard",
                        description=(
                            f"Policy '{policy_name}' allows Action='*' on Resource='*'."
                        ),
                        recommendation=(
                            "Restrict the policy to the specific actions and resources "
                            "this workload requires."
                        ),
                        evidence={"actions": actions, "resources": resources},
                    )
                )
            elif iam_wildcard and resource_is_wildcard:
                issues.append(
                    PostureIssue(
                        resource=policy_arn,
                        severity="CRITICAL",
                        rule="iam_policy_iam_wildcard",
                        description=(
                            f"Policy '{policy_name}' allows iam:* on Resource='*'."
                        ),
                        recommendation="Scope iam:* to specific resources and add conditions.",
                        evidence={"actions": actions, "resources": resources},
                    )
                )

            if any(a == "iam:PassRole" or a == "iam:*" or a == "*" for a in actions) and resource_is_wildcard and not condition:
                issues.append(
                    PostureIssue(
                        resource=policy_arn,
                        severity="HIGH",
                        rule="iam_policy_passrole_no_condition",
                        description=(
                            f"Policy '{policy_name}' grants iam:PassRole on '*' without a "
                            "Condition block — a privilege-escalation primitive."
                        ),
                        recommendation=(
                            "Add a Condition limiting iam:PassRole to a specific "
                            "set of role ARNs."
                        ),
                        evidence={"actions": actions, "resources": resources},
                    )
                )

            if not condition and (action_is_wildcard or resource_is_wildcard):
                issues.append(
                    PostureIssue(
                        resource=policy_arn,
                        severity="MEDIUM",
                        rule="iam_policy_missing_condition",
                        description=(
                            f"Policy '{policy_name}' has broad actions/resources but no "
                            "Condition block to scope them."
                        ),
                        recommendation=(
                            "Add a Condition (e.g. aws:RequestedRegion, "
                            "aws:SourceIp) to tighten the policy."
                        ),
                        evidence={"actions": actions, "resources": resources},
                    )
                )

    # --- S3 buckets ---------------------------------------------------------

    def _check_bucket_policies(self) -> list[PostureIssue]:
        issues: list[PostureIssue] = []
        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except ClientError:
            raise

        for bucket in buckets:
            bucket_name = bucket.get("Name")
            if not bucket_name:
                continue

            issues.extend(self._check_bucket_public_access_block(bucket_name))
            issues.extend(self._check_bucket_policy(bucket_name))
            issues.extend(self._check_bucket_encryption(bucket_name))
            issues.extend(self._check_bucket_versioning(bucket_name))

        return issues

    def _check_bucket_public_access_block(self, bucket_name: str) -> list[PostureIssue]:
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})
        except ClientError as exc:
            if self._is_access_denied(exc):
                raise
            return [
                PostureIssue(
                    resource=bucket_name,
                    severity="MEDIUM",
                    rule="s3_public_access_block_missing",
                    description=(
                        f"Bucket '{bucket_name}' has no PublicAccessBlock configuration."
                    ),
                    recommendation=(
                        "Enable all four PublicAccessBlock flags (BlockPublicAcls, "
                        "IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)."
                    ),
                )
            ]

        if not all(
            [
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ]
        ):
            return [
                PostureIssue(
                    resource=bucket_name,
                    severity="MEDIUM",
                    rule="s3_public_access_block_incomplete",
                    description=(
                        f"Bucket '{bucket_name}' has incomplete PublicAccessBlock "
                        f"settings: {config}."
                    ),
                    recommendation="Enable all four PublicAccessBlock flags.",
                    evidence={"current_config": config},
                )
            ]
        return []

    def _check_bucket_policy(self, bucket_name: str) -> list[PostureIssue]:
        try:
            response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response.get("Policy", "{}"))
        except ClientError as exc:
            if self._is_access_denied(exc):
                raise
            return []
        except json.JSONDecodeError:
            return [
                PostureIssue(
                    resource=bucket_name,
                    severity="LOW",
                    rule="s3_policy_unparseable",
                    description=f"Bucket '{bucket_name}' has an unparseable policy.",
                    recommendation="Review and rewrite the bucket policy in valid JSON.",
                )
            ]

        issues: list[PostureIssue] = []
        for statement in policy.get("Statement", []):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            is_public = False
            
            if principal == "*":
                is_public = True
            elif isinstance(principal, dict):
                for key in ["AWS", "Federated", "Service"]:
                    val = principal.get(key)
                    if val == "*" or (isinstance(val, list) and "*" in val):
                        is_public = True
                        break
            
            if is_public:
                issues.append(
                    PostureIssue(
                        resource=bucket_name,
                        severity="HIGH",
                        rule="s3_policy_public_allow",
                        description=(
                            f"Bucket '{bucket_name}' has an Allow statement with "
                            f"Principal='{principal}'."
                        ),
                        recommendation=(
                            "Replace wildcard principals with specific account/user "
                            "ARNs and add a Condition."
                        ),
                        evidence={"statement": statement},
                    )
                )
        return issues

    def _check_bucket_encryption(self, bucket_name: str) -> list[PostureIssue]:
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
            return []
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in {"ServerSideEncryptionConfigurationNotFoundError", "NoSuchEncryptionConfiguration"}:
                return [
                    PostureIssue(
                        resource=bucket_name,
                        severity="MEDIUM",
                        rule="s3_encryption_missing",
                        description=(
                            f"Bucket '{bucket_name}' has no default encryption "
                            "configuration."
                        ),
                        recommendation=(
                            "Configure default encryption with AES256 or "
                            "aws:kms and a customer-managed key."
                        ),
                    )
                ]
            if self._is_access_denied(exc):
                raise
            return []

    def _check_bucket_versioning(self, bucket_name: str) -> list[PostureIssue]:
        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status")
            if status != "Enabled":
                return [
                    PostureIssue(
                        resource=bucket_name,
                        severity="LOW",
                        rule="s3_versioning_disabled",
                        description=(
                            f"Bucket '{bucket_name}' versioning is '{status}'."
                        ),
                        recommendation="Enable versioning for data-recovery purposes.",
                    )
                ]
        except ClientError as exc:
            if self._is_access_denied(exc):
                raise
            return []
        return []

    # --- Access keys --------------------------------------------------------

    def _check_access_keys(self) -> list[PostureIssue]:
        issues: list[PostureIssue] = []
        try:
            users_paginator = self.iam_client.get_paginator("list_users")
            for page in users_paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user.get("UserName")
                    if not user_name:
                        continue
                    issues.extend(self._check_keys_for_user(user_name))
        except ClientError:
            raise
        return issues

    def _check_keys_for_user(self, user_name: str) -> list[PostureIssue]:
        issues: list[PostureIssue] = []
        try:
            keys = self.iam_client.list_access_keys(UserName=user_name).get(
                "AccessKeyMetadata", []
            )
        except ClientError:
            raise

        active_keys = [k for k in keys if k.get("Status") == "Active"]
        if len(active_keys) > 1:
            issues.append(
                PostureIssue(
                    resource=user_name,
                    severity="MEDIUM",
                    rule="iam_user_multiple_active_keys",
                    description=(
                        f"User '{user_name}' has {len(active_keys)} active access keys."
                    ),
                    recommendation=(
                        "Keep at most one active access key per user. Rotate or "
                        "deactivate the others."
                    ),
                )
            )

        for key in keys:
            key_id = key.get("AccessKeyId")
            create_date = key.get("CreateDate")
            status = key.get("Status")
            if not key_id or not create_date:
                continue

            now = datetime.now(timezone.utc)
            # boto3 returns naive datetimes for CreateDate; assume UTC.
            if create_date.tzinfo is None:
                create_date = create_date.replace(tzinfo=timezone.utc)
            age_days = (now - create_date).days

            if age_days >= KEY_AGE_CRITICAL_DAYS:
                severity = "CRITICAL"
            elif age_days >= KEY_AGE_HIGH_DAYS:
                severity = "HIGH"
            else:
                severity = None

            if severity:
                issues.append(
                    PostureIssue(
                        resource=f"{user_name}:{key_id}",
                        severity=severity,
                        rule="iam_access_key_age",
                        description=(
                            f"Access key {key_id} for '{user_name}' is {age_days} days old "
                            f"(status: {status})."
                        ),
                        recommendation="Rotate the access key.",
                        evidence={"age_days": age_days, "status": status},
                    )
                )

            try:
                usage = self.iam_client.get_access_key_last_used(AccessKeyId=key_id)
                last_used = usage.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if last_used is None and status == "Active":
                    issues.append(
                        PostureIssue(
                            resource=f"{user_name}:{key_id}",
                            severity="LOW",
                            rule="iam_access_key_never_used",
                            description=(
                                f"Active access key {key_id} for '{user_name}' has never "
                                "been used."
                            ),
                            recommendation=(
                                "Deactivate the key and remove it if not needed."
                            ),
                        )
                    )
            except ClientError:
                raise

        return issues

    # --- IAM user hygiene ---------------------------------------------------

    def _check_iam_users(self) -> list[PostureIssue]:
        issues: list[PostureIssue] = []

        # Account-level summary
        try:
            summary = self.iam_client.get_account_summary().get("SummaryMap", {})
        except ClientError:
            raise

        if summary and not summary.get("AccountMFAEnabled", True):
            issues.append(
                PostureIssue(
                    resource="account",
                    severity="HIGH",
                    rule="iam_account_mfa_disabled",
                    description="Root account does not have MFA enabled.",
                    recommendation="Enable MFA on the root account immediately.",
                )
            )

        # Password policy
        try:
            policy = self.iam_client.get_account_password_policy().get("PasswordPolicy", {})
        except ClientError as exc:
            if self._is_access_denied(exc):
                raise
            policy = None

        if policy is None:
            issues.append(
                PostureIssue(
                    resource="account",
                    severity="MEDIUM",
                    rule="iam_password_policy_missing",
                    description="No custom IAM password policy is configured.",
                    recommendation=(
                        "Configure a password policy with minimum length 14, "
                        "symbol requirement, and reuse prevention."
                    ),
                )
            )
        else:
            min_length = policy.get("MinimumPasswordLength", 0)
            if min_length < MIN_RECOMMENDED_PASSWORD_LENGTH:
                issues.append(
                    PostureIssue(
                        resource="account",
                        severity="MEDIUM",
                        rule="iam_password_policy_weak_length",
                        description=(
                            f"Password policy minimum length is {min_length}; "
                            f"recommended is >= {MIN_RECOMMENDED_PASSWORD_LENGTH}."
                        ),
                        recommendation=(
                            f"Increase MinimumPasswordLength to "
                            f"{MIN_RECOMMENDED_PASSWORD_LENGTH} or higher."
                        ),
                        evidence={"current_minimum": min_length},
                    )
                )
            if not policy.get("RequireSymbols", False):
                issues.append(
                    PostureIssue(
                        resource="account",
                        severity="LOW",
                        rule="iam_password_policy_no_symbols",
                        description="Password policy does not require symbols.",
                        recommendation="Enable RequireSymbols in the password policy.",
                    )
                )
            if not policy.get("PasswordReusePrevention", 0):
                issues.append(
                    PostureIssue(
                        resource="account",
                        severity="LOW",
                        rule="iam_password_policy_no_reuse_prevention",
                        description="Password policy does not prevent reuse.",
                        recommendation=(
                            "Set PasswordReusePrevention to a value >= 5."
                        ),
                    )
                )

        # Per-user MFA / password-last-set
        try:
            users_paginator = self.iam_client.get_paginator("list_users")
            for page in users_paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user.get("UserName")
                    if not user_name:
                        continue
                    issues.extend(self._check_user_mfa(user_name))
                    issues.extend(self._check_user_password_age(user_name))
        except ClientError:
            raise

        return issues

    def _check_user_mfa(self, user_name: str) -> list[PostureIssue]:
        try:
            devices = self.iam_client.list_mfa_devices(UserName=user_name).get(
                "MFADevices", []
            )
        except ClientError as exc:
            if self._is_access_denied(exc):
                raise
            return []

        if not devices:
            return [
                PostureIssue(
                    resource=user_name,
                    severity="MEDIUM",
                    rule="iam_user_no_mfa",
                    description=f"User '{user_name}' has no MFA device configured.",
                    recommendation="Enroll the user in MFA.",
                )
            ]
        return []

    def _check_user_password_age(self, user_name: str) -> list[PostureIssue]:
        try:
            login_profile_response = self.iam_client.get_login_profile(UserName=user_name)
            create_date = login_profile_response.get("LoginProfile", {}).get("CreateDate")
        except ClientError as exc:
            if self._is_access_denied(exc):
                raise
            return []

        if create_date is None:
            return []

        now = datetime.now(timezone.utc)
        if create_date.tzinfo is None:
            create_date = create_date.replace(tzinfo=timezone.utc)
        age_days = (now - create_date).days

        if age_days >= PASSWORD_AGE_MEDIUM_DAYS:
            return [
                PostureIssue(
                    resource=user_name,
                    severity="MEDIUM",
                    rule="iam_user_password_age",
                    description=(
                        f"User '{user_name}' password was created {age_days} days ago."
                    ),
                    recommendation="Rotate the user's password and review activity.",
                    evidence={"days_since_creation": age_days},
                )
            ]
        return []

    # --- Helpers ------------------------------------------------------------

    @staticmethod
    def _is_access_denied(exc: ClientError) -> bool:
        code = exc.response.get("Error", {}).get("Code", "")
        return code in {"AccessDenied", "UnauthorizedAccess", "AccessDeniedException"}

    @staticmethod
    def _safe(fn: Any, default: Any) -> Any:
        try:
            return fn()
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code in {"AccessDenied", "UnauthorizedAccess"}:
                return [
                    PostureIssue(
                        resource="<analyzer>",
                        severity="CRITICAL",
                        rule="aws_access_denied",
                        description=f"AWS API access denied: {exc}",
                        recommendation="Grant IAM permissions for posture analysis.",
                        evidence={"error_code": error_code, "operation": str(fn)},
                    )
                ] if default == [] else default
            logger.warning("Posture check raised; substituting default", exc_info=True)
            return [
                PostureIssue(
                    resource="<analyzer>",
                    severity="LOW",
                    rule="posture_check_failed",
                    description=f"Posture check failed: {exc}",
                    recommendation="Verify AWS credentials and IAM permissions.",
                )
            ] if default == [] else default
        except Exception as exc:
            logger.warning("Posture check raised; substituting default", exc_info=True)
            return [
                PostureIssue(
                    resource="<analyzer>",
                    severity="LOW",
                    rule="posture_check_failed",
                    description=f"Posture check failed: {exc}",
                    recommendation="Verify AWS credentials and IAM permissions.",
                )
            ] if default == [] else default

    @staticmethod
    def _section(issues: list[PostureIssue], label: str) -> dict[str, Any]:
        if not issues:
            return {
                "label": label,
                "issue_count": 0,
                "issues": [],
                "risk_score": 0.0,
                "risk_level": "LOW",
            }

        severity_weights = {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}
        total = sum(severity_weights.get(issue.severity, 1) for issue in issues)
        # Scale 0-10: divide by number of issues and weight by 1, capped at 10.
        raw = total / len(issues)
        # Each issue contributes up to 10; we take average, then bump if many
        # issues: log scale nudges high issue counts upward.
        if len(issues) > 5:
            raw = min(10.0, raw * 1.5)
        score = round(min(10.0, raw), 1)

        if score >= 8:
            level = "CRITICAL"
        elif score >= 6:
            level = "HIGH"
        elif score >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "label": label,
            "issue_count": len(issues),
            "issues": [issue.to_dict() for issue in issues],
            "risk_score": score,
            "risk_level": level,
        }

    @staticmethod
    def _overall(sections: list[dict[str, Any]]) -> dict[str, Any]:
        """Overall risk = the worst section, not an average.

        An account with one CRITICAL area and three clean areas should not
        look "mostly fine" on the headline number.
        """
        scores = [s.get("risk_score", 0) for s in sections]
        if not scores:
            return {"score": 0.0, "level": "LOW", "total_issues": 0}
        top = max(scores)
        if top >= 8:
            level = "CRITICAL"
        elif top >= 6:
            level = "HIGH"
        elif top >= 3:
            level = "MEDIUM"
        else:
            level = "LOW"
        return {
            "score": round(top, 1),
            "level": level,
            "total_issues": sum(s.get("issue_count", 0) for s in sections),
        }

    @staticmethod
    def _summary(sections: list[dict[str, Any]]) -> str:
        parts = []
        for section in sections:
            label = section.get("label", "")
            score = section.get("risk_score", 0)
            level = section.get("risk_level", "UNKNOWN")
            count = section.get("issue_count", 0)
            parts.append(f"{label}: {level} ({count} issues, score {score}/10)")
        return " | ".join(parts) if parts else "No issues found"
