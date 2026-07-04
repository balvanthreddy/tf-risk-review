"""Storage exposure and durability rules."""

from __future__ import annotations

from typing import ClassVar

from tf_risk_review.models import Action, Finding, ResourceChange, Severity
from tf_risk_review.rules.base import ResourceRule

_CHANGE_ACTIONS = (Action.CREATE, Action.UPDATE, Action.REPLACE)


class PublicS3Exposure(ResourceRule):
    """STO001: S3 public-access guardrails removed or public ACLs granted."""

    id = "STO001"
    default_severity = Severity.HIGH

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS:
            return []

        findings: list[Finding] = []

        if change.resource_type == "aws_s3_bucket_public_access_block":
            disabled = [
                attr
                for attr in (
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                )
                if change.after_value(attr) is False
            ]
            if disabled and (
                change.action is not Action.UPDATE or any(change.changed(attr) for attr in disabled)
            ):
                findings.append(
                    self.finding(
                        change,
                        title="S3 public access block weakened",
                        detail=(
                            "The public access block is the account's seatbelt against "
                            "accidental public buckets; disabling parts of it re-enables "
                            "the whole class of S3 data-leak incidents."
                        ),
                        evidence=f"disabled: {', '.join(disabled)}",
                        remediation=(
                            "Keep all four flags true. For genuinely public content, "
                            "serve it via CloudFront with OAC instead of a public bucket."
                        ),
                    )
                )

        if change.resource_type in ("aws_s3_bucket", "aws_s3_bucket_acl"):
            acl = change.after_value("acl")
            if acl in ("public-read", "public-read-write") and (
                change.action is not Action.UPDATE or change.changed("acl")
            ):
                findings.append(
                    self.finding(
                        change,
                        title=f"S3 bucket ACL is {acl}",
                        detail="Object listing/reading (and possibly writing) is open to everyone.",
                        evidence=f"acl: {acl}",
                        remediation=(
                            "Use private ACLs; grant access via bucket policy to principals."
                        ),
                    )
                )

        return findings


class EncryptionDisabled(ResourceRule):
    """STO002: at-rest encryption off for new or changed resources."""

    id = "STO002"
    default_severity = Severity.HIGH

    _ATTR_BY_TYPE: ClassVar[dict[str, str | None]] = {
        "aws_db_instance": "storage_encrypted",
        "aws_rds_cluster": "storage_encrypted",
        "aws_ebs_volume": "encrypted",
        "aws_efs_file_system": "encrypted",
        "aws_redshift_cluster": "encrypted",
        "aws_dynamodb_table": None,  # handled via server_side_encryption block
    }

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action not in _CHANGE_ACTIONS:
            return []
        attr = self._ATTR_BY_TYPE.get(change.resource_type, "missing")
        if attr == "missing":
            return []

        if attr is None:  # dynamodb
            sse = change.after_value("server_side_encryption", "enabled")
            unencrypted = sse is False
            evidence = "server_side_encryption.enabled: false"
        else:
            unencrypted = change.after_value(attr) is False
            evidence = f"{attr}: false"

        if not unencrypted:
            return []
        if change.action is Action.UPDATE and attr is not None and not change.changed(attr):
            return []

        return [
            self.finding(
                change,
                title=f"At-rest encryption disabled on {change.resource_type}",
                detail=(
                    "Unencrypted storage fails most compliance baselines (NIST, CIS, "
                    "HIPAA) and cannot always be encrypted in place later — RDS, for "
                    "example, requires a snapshot-restore migration."
                ),
                evidence=evidence,
                remediation="Enable encryption at creation; it is free and irreversible-cheap now.",
            )
        ]


class DurabilityWeakened(ResourceRule):
    """STO003: backups or versioning reduced on an existing resource."""

    id = "STO003"
    default_severity = Severity.MEDIUM

    def check(self, change: ResourceChange) -> list[Finding]:
        if change.action is not Action.UPDATE:
            return []

        findings: list[Finding] = []

        if change.resource_type in ("aws_db_instance", "aws_rds_cluster"):
            before = change.before_value("backup_retention_period")
            after = change.after_value("backup_retention_period")
            if isinstance(before, int) and isinstance(after, int) and after < before:
                severity_note = " (automated backups fully disabled)" if after == 0 else ""
                findings.append(
                    self.finding(
                        change,
                        title=f"Backup retention reduced: {before} -> {after} days{severity_note}",
                        detail="Shrinking the backup window shrinks the recovery window.",
                        evidence=f"backup_retention_period: {before} -> {after}",
                        remediation="Confirm the new window still meets the service's RPO.",
                    )
                )

        if change.resource_type == "aws_s3_bucket_versioning":
            before = change.before_value("versioning_configuration", "status")
            after = change.after_value("versioning_configuration", "status")
            if before == "Enabled" and after in ("Suspended", "Disabled"):
                findings.append(
                    self.finding(
                        change,
                        title="S3 versioning suspended",
                        detail=(
                            "Versioning is the undo button for overwrites and deletes; "
                            "suspending it removes that protection for new writes."
                        ),
                        evidence=f"versioning: {before} -> {after}",
                        remediation=(
                            "Keep versioning on; control cost with lifecycle rules instead."
                        ),
                    )
                )

        return findings
