"""IAM rules: privilege widening hides in JSON strings.

IAM policies arrive in the plan as JSON *strings* inside resource
attributes, so text-level plan review sees one long quoted blob. These
rules parse the documents and inspect the statements.
"""

from __future__ import annotations

import json
from dataclasses import replace
from typing import Any

from tf_risk_review.models import Action, Finding, ResourceChange, Severity
from tf_risk_review.rules.base import ResourceRule

_POLICY_BEARING_TYPES = frozenset(
    {
        "aws_iam_policy",
        "aws_iam_role_policy",
        "aws_iam_user_policy",
        "aws_iam_group_policy",
        "aws_s3_bucket_policy",
        "aws_sqs_queue_policy",
        "aws_sns_topic_policy",
    }
)

_CHANGE_ACTIONS = (Action.CREATE, Action.UPDATE, Action.REPLACE)


def _statements(document: Any) -> list[dict[str, Any]]:
    """Parse a policy document (JSON string or dict) into statement dicts."""
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except json.JSONDecodeError:
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [s for s in statements if isinstance(s, dict)]


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _policy_changed(change: ResourceChange, attr: str) -> bool:
    return change.action is not Action.UPDATE or change.changed(attr)


class WildcardPolicy(ResourceRule):
    """IAM001: Allow statements with wildcard actions or resources."""

    id = "IAM001"
    default_severity = Severity.HIGH

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS:
            return []
        if change.resource_type not in _POLICY_BEARING_TYPES:
            return []
        if not _policy_changed(change, "policy"):
            return []

        findings: list[Finding] = []
        for statement in _statements(change.after_value("policy")):
            if statement.get("Effect") != "Allow":
                continue
            actions = _as_list(statement.get("Action"))
            resources = _as_list(statement.get("Resource"))
            wildcard_action = any(a == "*" for a in actions)
            wildcard_resource = any(r == "*" for r in resources)
            uses_not_action = "NotAction" in statement

            if wildcard_action and wildcard_resource:
                finding = self.finding(
                    change,
                    title="Policy allows * on * (full admin)",
                    detail=(
                        "This statement grants every action on every resource — "
                        "administrator access by construction."
                    ),
                    evidence='{"Effect": "Allow", "Action": "*", "Resource": "*"}',
                    remediation="Scope actions to the services needed and resources to ARNs.",
                )
                # Full admin escalates above the rule's default severity.
                findings.append(replace(finding, severity=Severity.CRITICAL))
            elif wildcard_action:
                findings.append(
                    self.finding(
                        change,
                        title="Policy allows Action: *",
                        detail="Every API action is allowed on the listed resources.",
                        evidence=f"Action: * on Resource: {resources or ['(none)']}",
                        remediation="Enumerate the actions this workload actually calls.",
                    )
                )
            elif uses_not_action:
                findings.append(
                    self.finding(
                        change,
                        title="Policy uses NotAction with Allow",
                        detail=(
                            "Allow+NotAction grants everything *except* the listed "
                            "actions — it widens silently every time AWS ships a new "
                            "API."
                        ),
                        evidence=f"NotAction: {_as_list(statement.get('NotAction'))}",
                        remediation="Invert into an explicit Action allowlist.",
                    )
                )
            elif wildcard_resource and any(_is_write_action(a) for a in actions):
                findings.append(
                    self.finding(
                        change,
                        title="Write actions allowed on Resource: *",
                        detail="Mutating actions are unscoped — they apply account-wide.",
                        evidence=f"Action: {actions[:5]} on Resource: *",
                        remediation="Scope Resource to the specific ARNs this role manages.",
                    )
                )
        return findings


def _is_write_action(action: str) -> bool:
    if ":" not in action:
        return True  # malformed/unknown — assume the worse case
    verb = action.split(":", 1)[1]
    read_prefixes = ("Get", "List", "Describe", "Read", "Lookup", "Select", "Query", "Scan")
    return not verb.startswith(read_prefixes)


class OpenTrustPolicy(ResourceRule):
    """IAM002: a role's trust policy lets anyone assume it."""

    id = "IAM002"
    default_severity = Severity.CRITICAL

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS or change.resource_type != "aws_iam_role":
            return []
        if not _policy_changed(change, "assume_role_policy"):
            return []

        findings: list[Finding] = []
        for statement in _statements(change.after_value("assume_role_policy")):
            if statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            open_principal = principal == "*" or (
                isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))
            )
            if open_principal and not statement.get("Condition"):
                findings.append(
                    self.finding(
                        change,
                        title="Role assumable by any principal",
                        detail=(
                            "Principal '*' without a Condition means any AWS account "
                            "can assume this role and inherit its permissions."
                        ),
                        evidence=f"Principal: {principal}",
                        remediation=(
                            "Restrict Principal to specific account/role ARNs, or add "
                            "a Condition (e.g. source account/OIDC subject) if a broad "
                            "principal is genuinely required."
                        ),
                    )
                )
        return findings


class AdminPolicyAttachment(ResourceRule):
    """IAM003: AdministratorAccess (or equivalent) attached."""

    id = "IAM003"
    default_severity = Severity.HIGH

    _ATTACH_TYPES = frozenset(
        {
            "aws_iam_role_policy_attachment",
            "aws_iam_user_policy_attachment",
            "aws_iam_group_policy_attachment",
            "aws_iam_policy_attachment",
        }
    )
    _ADMIN_SUFFIXES = (
        "policy/AdministratorAccess",
        "policy/PowerUserAccess",
        "policy/IAMFullAccess",
    )

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS:
            return []
        if change.resource_type not in self._ATTACH_TYPES:
            return []
        arn = str(change.after_value("policy_arn") or "")
        if not arn.endswith(self._ADMIN_SUFFIXES):
            return []
        return [
            self.finding(
                change,
                title=f"High-privilege managed policy attached: {arn.rsplit('/', 1)[-1]}",
                detail="Broad managed policies bypass least-privilege review entirely.",
                evidence=f"policy_arn: {arn}",
                remediation="Attach a scoped customer-managed policy instead.",
            )
        ]


class StaticAccessKey(ResourceRule):
    """IAM004: long-lived credentials created."""

    id = "IAM004"
    default_severity = Severity.MEDIUM

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action is not Action.CREATE or change.resource_type != "aws_iam_access_key":
            return []
        return [
            self.finding(
                change,
                title="Static IAM access key created",
                detail=(
                    "Long-lived keys don't expire and end up in CI variables and "
                    "laptops. Most workloads can use short-lived credentials instead."
                ),
                evidence=f"aws_iam_access_key for user: {change.after_value('user') or 'unknown'}",
                remediation=(
                    "Prefer IAM roles (IRSA, instance profiles, OIDC federation for "
                    "CI). If a key is unavoidable, add rotation and scope the user."
                ),
            )
        ]
