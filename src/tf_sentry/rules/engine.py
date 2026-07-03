"""Rule execution engine.

Applies per-repo configuration (disable, severity override, address
ignores) *around* the rules, so rules themselves stay pure functions of
their input — which is what makes the detection corpus trustworthy.
"""

from __future__ import annotations

from dataclasses import replace

from tf_sentry.config import ReviewConfig
from tf_sentry.models import Finding, ResourceChange
from tf_sentry.rules.base import PlanRule, ResourceRule
from tf_sentry.rules.deletions import (
    BlastRadius,
    DeletionProtectionDisabled,
    ForceDestroyEnabled,
    StatefulDeletion,
    StatefulReplacement,
)
from tf_sentry.rules.iam import (
    AdminPolicyAttachment,
    OpenTrustPolicy,
    StaticAccessKey,
    WildcardPolicy,
)
from tf_sentry.rules.network import OpenIngress, PubliclyAccessibleDatabase
from tf_sentry.rules.storage import DurabilityWeakened, EncryptionDisabled, PublicS3Exposure


def default_resource_rules() -> list[ResourceRule]:
    return [
        StatefulDeletion(),
        StatefulReplacement(),
        ForceDestroyEnabled(),
        DeletionProtectionDisabled(),
        WildcardPolicy(),
        OpenTrustPolicy(),
        AdminPolicyAttachment(),
        StaticAccessKey(),
        OpenIngress(),
        PubliclyAccessibleDatabase(),
        PublicS3Exposure(),
        EncryptionDisabled(),
        DurabilityWeakened(),
    ]


def default_plan_rules(config: ReviewConfig) -> list[PlanRule]:
    return [BlastRadius(max_deletes=config.max_deletes)]


def run_rules(
    changes: list[ResourceChange],
    config: ReviewConfig,
    resource_rules: list[ResourceRule] | None = None,
    plan_rules: list[PlanRule] | None = None,
) -> list[Finding]:
    resource_rules = resource_rules if resource_rules is not None else default_resource_rules()
    plan_rules = plan_rules if plan_rules is not None else default_plan_rules(config)

    considered = [c for c in changes if not config.is_ignored(c.address)]

    findings: list[Finding] = []
    for change in considered:
        for rule in resource_rules:
            override = config.override_for(rule.id)
            if not override.enabled:
                continue
            for finding in rule.check(change):
                if override.severity is not None:
                    finding = replace(finding, severity=override.severity)
                findings.append(finding)

    for plan_rule in plan_rules:
        override = config.override_for(plan_rule.id)
        if not override.enabled:
            continue
        for finding in plan_rule.check_plan(considered):
            if override.severity is not None:
                finding = replace(finding, severity=override.severity)
            findings.append(finding)

    # Highest severity first, then stable by address and rule for
    # deterministic reports (diffs of report output should mean something).
    findings.sort(key=lambda f: (-int(f.severity), f.address, f.rule_id))
    return findings
