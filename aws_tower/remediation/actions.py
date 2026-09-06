"""Remediation actions executed against AWS.

These are the concrete boto3-backed actions the remediation planner can assemble
into a plan. They contain no LLM logic; they only translate an action name and a
parameters dict into one or more AWS API calls and return a result dict.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)


class RemediationActions:
    """Execute concrete remediation actions against AWS APIs.

    Each public method returns a dict describing what happened. Methods are
    safe to call independently of the planner; the planner just decides which
    ones to call and in what order.
    """

    def __init__(self, boto3_session: Any | None = None) -> None:
        self._session = boto3_session
        self._iam_client: Any | None = None
        self._s3_client: Any | None = None
        self._ec2_client: Any | None = None

    @property
    def session(self) -> Any:
        if self._session is None:
            self._session = boto3.Session()
        return self._session

    @property
    def iam_client(self) -> Any:
        if self._iam_client is None:
            self._iam_client = self.session.client("iam")
        return self._iam_client

    @property
    def s3_client(self) -> Any:
        if self._s3_client is None:
            self._s3_client = self.session.client("s3")
        return self._s3_client

    @property
    def ec2_client(self) -> Any:
        if self._ec2_client is None:
            self._ec2_client = self.session.client("ec2")
        return self._ec2_client

    def execute(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        """Dispatch an action by name to the matching concrete method."""
        if action == "revoke_session":
            return self.revoke_session(params)
        if action == "deactivate_key":
            return self.deactivate_access_key(params)
        if action == "block_ip":
            return self.add_ip_to_blocklist(params)
        if action == "update_bucket_policy":
            return self.update_bucket_policy(params)
        if action == "revoke_role_session":
            return self.revoke_role_session(params)
        if action == "enable_public_access_block":
            return self.enable_public_access_block(params)
        if action == "detach_user_policy":
            return self.detach_user_policy(params)
        return {"error": f"Unknown action: {action}"}

    def revoke_session(self, params: dict[str, Any]) -> dict[str, Any]:
        """Remove a signing certificate associated with an IAM user.

        NOTE: this is the closest built-in approximation to "revoke a session"
        we can perform without STS session-revocation APIs. Pass a certificate
        ID, not a session ID.
        """
        user_name = params.get("user_name")
        certificate_id = params.get("session_id")

        if not user_name or not certificate_id:
            return {"error": "user_name and session_id are required"}

        try:
            self.iam_client.delete_signing_certificate(
                UserName=user_name,
                CertificateId=certificate_id,
            )
            return {
                "action": "revoke_session",
                "user": user_name,
                "certificate_id": certificate_id,
                "status": "REVOKED",
            }
        except (ClientError, BotoCoreError) as exc:
            logger.warning("revoke_session failed for %s", user_name, exc_info=True)
            return {"action": "revoke_session", "error": str(exc)}

    def deactivate_access_key(self, params: dict[str, Any]) -> dict[str, Any]:
        """Mark an IAM access key as inactive."""
        user_name = params.get("user_name")
        access_key_id = params.get("access_key_id")

        if not user_name or not access_key_id:
            return {"error": "user_name and access_key_id are required"}

        try:
            self.iam_client.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status="Inactive",
            )
            return {
                "action": "deactivate_key",
                "user": user_name,
                "access_key_id": access_key_id,
                "status": "DEACTIVATED",
            }
        except (ClientError, BotoCoreError) as exc:
            logger.warning("deactivate_key failed for %s", user_name, exc_info=True)
            return {"action": "deactivate_key", "error": str(exc)}

    def add_ip_to_blocklist(self, params: dict[str, Any]) -> dict[str, Any]:
        """Produce recommendations for blocking an IP across AWS controls.

        No AWS call is made directly; instead, the caller can take the
        recommendations and apply them via WAF, security groups, or NACLs.
        """
        ip_address = params.get("ip_address")
        reason = params.get("reason", "Suspicious activity")

        if not ip_address:
            return {"error": "ip_address is required"}

        return {
            "action": "block_ip",
            "ip_address": ip_address,
            "reason": reason,
            "recommendations": {
                "aws_waf": f"Add {ip_address} to IP set for web ACL",
                "security_group": f"Add inbound deny rule for {ip_address}/32",
                "network_acl": f"Add inbound deny rule for {ip_address}/32",
                "cloudwatch_alarm": f"Create alarm for traffic from {ip_address}",
            },
            "executed": False,
        }

    def update_bucket_policy(self, params: dict[str, Any]) -> dict[str, Any]:
        """Append a Deny statement to a bucket's policy.

        The prior policy is snapshotted into the result under
        `prior_policy` so a follow-up step (or operator) can revert if
        the new statement breaks something. The snapshot is only present
        when an existing policy was read; for new buckets it is `None`.
        """
        import copy

        bucket_name = params.get("bucket_name")
        effect = params.get("effect", "Deny")
        principal = params.get("principal", "*")

        if not bucket_name:
            return {"error": "bucket_name is required"}

        prior_policy: dict[str, Any] | None = None
        had_existing_policy = False

        try:
            try:
                current_policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                raw = current_policy.get("Policy", "{}")
                parsed = json.loads(raw) if raw else None
                # Deep-copy so the snapshot we return isn't mutated when
                # we append the new statement below.
                prior_policy = copy.deepcopy(parsed) if parsed else None
                had_existing_policy = prior_policy is not None
                policy_document = parsed or {"Version": "2012-10-17", "Statement": []}
            except Exception:
                policy_document = {"Version": "2012-10-17", "Statement": []}

            new_statement = {
                "Sid": f"Block{principal.replace('*', 'All')}{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                "Effect": effect,
                "Principal": {"AWS": principal} if principal != "*" else {"AWS": "*"},
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*",
                ],
            }

            policy_document["Statement"].append(new_statement)

            self.s3_client.put_bucket_policy(
                Bucket=bucket_name,
                Policy=json.dumps(policy_document),
            )

            return {
                "action": "update_bucket_policy",
                "bucket": bucket_name,
                "status": "UPDATED",
                "had_existing_policy": had_existing_policy,
                "prior_policy": prior_policy,
                "new_statement": new_statement,
            }
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "update_bucket_policy failed for %s", bucket_name, exc_info=True
            )
            return {"action": "update_bucket_policy", "error": str(exc)}
        except json.JSONDecodeError as exc:
            logger.warning(
                "update_bucket_policy failed to parse existing policy for %s", bucket_name, exc_info=True
            )
            return {"action": "update_bucket_policy", "error": f"Invalid JSON in existing policy: {exc}"}

    def enable_public_access_block(self, params: dict[str, Any]) -> dict[str, Any]:
        """Enable all four S3 public-access-block flags on a bucket."""
        bucket_name = params.get("bucket_name")
        if not bucket_name:
            return {"error": "bucket_name is required"}

        try:
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            return {
                "action": "enable_public_access_block",
                "bucket": bucket_name,
                "status": "ENABLED",
            }
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "enable_public_access_block failed for %s", bucket_name, exc_info=True
            )
            return {"action": "enable_public_access_block", "error": str(exc)}

    def detach_user_policy(self, params: dict[str, Any]) -> dict[str, Any]:
        """Detach a managed policy from an IAM user."""
        user_name = params.get("user_name")
        policy_arn = params.get("policy_arn")

        if not user_name or not policy_arn:
            return {"error": "user_name and policy_arn are required"}

        try:
            self.iam_client.detach_user_policy(
                UserName=user_name,
                PolicyArn=policy_arn,
            )
            return {
                "action": "detach_user_policy",
                "user": user_name,
                "policy_arn": policy_arn,
                "status": "DETACHED",
            }
        except (ClientError, BotoCoreError) as exc:
            logger.warning(
                "detach_user_policy failed for %s", user_name, exc_info=True
            )
            return {"action": "detach_user_policy", "error": str(exc)}

    def revoke_role_session(self, params: dict[str, Any]) -> dict[str, Any]:
        """Note an STS role session for cleanup.

        STS does not provide direct session revocation. The action returns a
        suggested-cleanup record so the caller can rotate credentials and
        monitor subsequent activity.
        """
        role_arn = params.get("role_arn")
        session_name = params.get("session_name")

        if not role_arn or not session_name:
            return {"error": "role_arn and session_name are required"}

        return {
            "action": "revoke_role_session",
            "role": role_arn,
            "session": session_name,
            "status": "SUGGESTED_CLEANUP",
            "note": "Role sessions cannot be directly revoked; rotate credentials and monitor.",
        }
