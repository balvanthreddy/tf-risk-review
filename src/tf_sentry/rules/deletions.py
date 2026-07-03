"""Rules for destructive changes to stateful resources.

Deleting a compute instance loses minutes; deleting a database loses
data. These rules exist because both render identically in plan output —
one line starting with ``-``.
"""

from __future__ import annotations

from tf_sentry.models import Action, Finding, ResourceChange, Severity
from tf_sentry.rules.base import PlanRule, ResourceRule

# Resource types whose destruction destroys data or irrecoverable state,
# not just infrastructure. Kept intentionally explicit: reviewability of
# this list is the point.
STATEFUL_TYPES: frozenset[str] = frozenset(
    {
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_rds_cluster_instance",
        "aws_dynamodb_table",
        "aws_s3_bucket",
        "aws_ebs_volume",
        "aws_efs_file_system",
        "aws_elasticache_cluster",
        "aws_elasticache_replication_group",
        "aws_redshift_cluster",
        "aws_opensearch_domain",
        "aws_elasticsearch_domain",
        "aws_secretsmanager_secret",
        "aws_kms_key",
        "aws_backup_vault",
        "aws_cloudwatch_log_group",
        "azurerm_postgresql_flexible_server",
        "azurerm_mssql_database",
        "azurerm_storage_account",
        "azurerm_key_vault",
        "google_sql_database_instance",
        "google_storage_bucket",
    }
)


class StatefulDeletion(ResourceRule):
    """DEL001: a data-bearing resource is being destroyed."""

    id = "DEL001"
    default_severity = Severity.CRITICAL

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action is not Action.DELETE or change.resource_type not in STATEFUL_TYPES:
            return []
        return [
            self.finding(
                change,
                title=f"Stateful resource destroyed: {change.resource_type}",
                detail=(
                    "This delete destroys data or irrecoverable state, not just "
                    "infrastructure. Verify a backup/snapshot exists and that the "
                    "deletion is intentional, not a rename or refactor side effect."
                ),
                evidence=f"plan action: delete on {change.address}",
                remediation=(
                    "If this is a rename/move, use a `moved` block or `terraform state mv` "
                    "instead of destroy-and-recreate. If intentional, confirm final "
                    "snapshots/backups before merging."
                ),
            )
        ]


class StatefulReplacement(ResourceRule):
    """DEL002: a data-bearing resource is destroyed and recreated."""

    id = "DEL002"
    default_severity = Severity.HIGH

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action is not Action.REPLACE or change.resource_type not in STATEFUL_TYPES:
            return []
        forcing = ", ".join(change.replace_paths) or "not reported by provider"
        return [
            self.finding(
                change,
                title=f"Stateful resource replaced: {change.resource_type}",
                detail=(
                    "Replacement destroys the existing resource. The new one starts "
                    "empty — data does not follow."
                ),
                evidence=f"attribute(s) forcing replacement: {forcing}",
                remediation=(
                    "Check whether the forcing attribute can change in place (or was "
                    "an accidental edit). Consider create_before_destroy plus a "
                    "migration step if replacement is truly required."
                ),
            )
        ]


class ForceDestroyEnabled(ResourceRule):
    """DEL003: force_destroy turned on — deletion protection removed in advance."""

    id = "DEL003"
    default_severity = Severity.HIGH

    _TYPES = frozenset({"aws_s3_bucket", "aws_ecr_repository", "aws_mq_broker"})

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in (Action.CREATE, Action.UPDATE, Action.REPLACE):
            return []
        if change.resource_type not in self._TYPES:
            return []
        if change.after_value("force_destroy") is not True:
            return []
        if change.action is Action.UPDATE and not change.changed("force_destroy"):
            return []
        return [
            self.finding(
                change,
                title="force_destroy enabled",
                detail=(
                    "With force_destroy=true, a later `terraform destroy` (or a "
                    "refactor that removes this resource) deletes all contents "
                    "without any safety stop."
                ),
                evidence="force_destroy: true",
                remediation=(
                    "Keep force_destroy=false for anything holding real data; enable "
                    "it temporarily and explicitly only when decommissioning."
                ),
            )
        ]


class DeletionProtectionDisabled(ResourceRule):
    """DEL004: an existing resource's deletion protection is being switched off."""

    id = "DEL004"
    default_severity = Severity.HIGH

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action is not Action.UPDATE:
            return []
        if not (
            change.before_value("deletion_protection") is True
            and change.after_value("deletion_protection") is False
        ):
            return []
        return [
            self.finding(
                change,
                title="Deletion protection disabled",
                detail=(
                    "Turning off deletion protection is usually the first commit of a "
                    "two-step destroy. Review as if the delete were in this PR."
                ),
                evidence="deletion_protection: true -> false",
                remediation="If decommissioning, link the runbook/ticket authorizing it.",
            )
        ]


class BlastRadius(PlanRule):
    """DEL900: unusually many deletions in one plan.

    Individually-fine deletes can aggregate into an incident (a refactor
    that renames a module, a workspace pointed at the wrong state file).
    """

    id = "DEL900"
    default_severity = Severity.HIGH

    def __init__(self, max_deletes: int) -> None:
        self._max_deletes = max_deletes

    def check_plan(self, changes: list[ResourceChange]) -> list[Finding]:
        deletions = [c.address for c in changes if c.action in (Action.DELETE, Action.REPLACE)]
        if len(deletions) <= self._max_deletes:
            return []
        shown = ", ".join(deletions[:8]) + ("…" if len(deletions) > 8 else "")
        return [
            Finding(
                rule_id=self.id,
                severity=self.default_severity,
                address="(plan-wide)",
                title=f"{len(deletions)} resources destroyed or replaced in one plan",
                detail=(
                    "Large simultaneous destruction is the signature of a refactor "
                    "gone wrong (state mismatch, renamed module, wrong workspace) — "
                    "or a genuinely large decommission that deserves a staged rollout."
                ),
                evidence=f"affected: {shown}",
                remediation=(
                    "Verify against the intended change scope; consider applying in "
                    "stages or using `moved` blocks for renames."
                ),
            )
        ]
