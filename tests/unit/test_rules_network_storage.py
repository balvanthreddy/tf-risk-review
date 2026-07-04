from __future__ import annotations

from tests.factories import change
from tf_risk_review.models import Action, Severity
from tf_risk_review.rules.network import OpenIngress, PubliclyAccessibleDatabase
from tf_risk_review.rules.storage import DurabilityWeakened, EncryptionDisabled, PublicS3Exposure


def _sg(ingress: list[dict]) -> dict:
    return {"name": "sg", "ingress": ingress, "egress": []}


class TestOpenIngress:
    def test_world_ssh_is_critical(self) -> None:
        [finding] = OpenIngress().check(
            change(
                "aws_security_group",
                Action.CREATE,
                after=_sg(
                    [
                        {
                            "cidr_blocks": ["0.0.0.0/0"],
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                        }
                    ]
                ),
            )
        )
        assert finding.severity is Severity.CRITICAL
        assert "SSH" in finding.detail

    def test_world_https_is_high_not_critical(self) -> None:
        [finding] = OpenIngress().check(
            change(
                "aws_security_group",
                Action.CREATE,
                after=_sg(
                    [
                        {
                            "cidr_blocks": ["0.0.0.0/0"],
                            "from_port": 443,
                            "to_port": 443,
                            "protocol": "tcp",
                        }
                    ]
                ),
            )
        )
        assert finding.severity is Severity.HIGH

    def test_all_traffic_is_critical(self) -> None:
        [finding] = OpenIngress().check(
            change(
                "aws_security_group",
                Action.CREATE,
                after=_sg(
                    [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 0, "to_port": 0, "protocol": "-1"}]
                ),
            )
        )
        assert finding.severity is Severity.CRITICAL

    def test_port_range_covering_database_is_critical(self) -> None:
        [finding] = OpenIngress().check(
            change(
                "aws_security_group",
                Action.CREATE,
                after=_sg(
                    [
                        {
                            "cidr_blocks": ["::/0"],
                            "from_port": 5000,
                            "to_port": 6000,
                            "protocol": "tcp",
                        }
                    ]
                ),
            )
        )
        assert "PostgreSQL" in finding.detail

    def test_private_cidr_clean(self) -> None:
        assert (
            OpenIngress().check(
                change(
                    "aws_security_group",
                    Action.CREATE,
                    after=_sg(
                        [
                            {
                                "cidr_blocks": ["10.0.0.0/8"],
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                            }
                        ]
                    ),
                )
            )
            == []
        )

    def test_standalone_ingress_rule_resource(self) -> None:
        [finding] = OpenIngress().check(
            change(
                "aws_vpc_security_group_ingress_rule",
                Action.CREATE,
                after={
                    "cidr_ipv4": "0.0.0.0/0",
                    "from_port": 3389,
                    "to_port": 3389,
                    "ip_protocol": "tcp",
                },
            )
        )
        assert finding.severity is Severity.CRITICAL
        assert "RDP" in finding.detail


class TestPubliclyAccessibleDatabase:
    def test_flip_to_public_flagged(self) -> None:
        [finding] = PubliclyAccessibleDatabase().check(
            change(
                "aws_db_instance",
                Action.UPDATE,
                before={"publicly_accessible": False},
                after={"publicly_accessible": True},
            )
        )
        assert finding.rule_id == "NET002"

    def test_already_public_unchanged_silent(self) -> None:
        assert (
            PubliclyAccessibleDatabase().check(
                change(
                    "aws_db_instance",
                    Action.UPDATE,
                    before={"publicly_accessible": True, "tags": {}},
                    after={"publicly_accessible": True, "tags": {"a": "b"}},
                )
            )
            == []
        )


class TestPublicS3Exposure:
    def test_weakened_access_block_flagged(self) -> None:
        [finding] = PublicS3Exposure().check(
            change(
                "aws_s3_bucket_public_access_block",
                Action.UPDATE,
                before={"block_public_acls": True, "block_public_policy": True},
                after={"block_public_acls": False, "block_public_policy": True},
            )
        )
        assert "block_public_acls" in finding.evidence

    def test_public_acl_flagged(self) -> None:
        [finding] = PublicS3Exposure().check(
            change("aws_s3_bucket_acl", Action.CREATE, after={"acl": "public-read"})
        )
        assert "public-read" in finding.title

    def test_private_acl_clean(self) -> None:
        assert (
            PublicS3Exposure().check(
                change("aws_s3_bucket_acl", Action.CREATE, after={"acl": "private"})
            )
            == []
        )


class TestEncryptionDisabled:
    def test_unencrypted_volume_flagged(self) -> None:
        [finding] = EncryptionDisabled().check(
            change("aws_ebs_volume", Action.CREATE, after={"encrypted": False})
        )
        assert finding.rule_id == "STO002"

    def test_encrypted_volume_clean(self) -> None:
        assert (
            EncryptionDisabled().check(
                change("aws_ebs_volume", Action.CREATE, after={"encrypted": True})
            )
            == []
        )

    def test_dynamodb_sse_disabled_flagged(self) -> None:
        [finding] = EncryptionDisabled().check(
            change(
                "aws_dynamodb_table",
                Action.CREATE,
                after={"server_side_encryption": [{"enabled": False}]},
            )
        )
        assert "server_side_encryption" in finding.evidence


class TestDurabilityWeakened:
    def test_backup_retention_reduced(self) -> None:
        [finding] = DurabilityWeakened().check(
            change(
                "aws_db_instance",
                Action.UPDATE,
                before={"backup_retention_period": 14},
                after={"backup_retention_period": 0},
            )
        )
        assert "fully disabled" in finding.title

    def test_backup_retention_increased_clean(self) -> None:
        assert (
            DurabilityWeakened().check(
                change(
                    "aws_db_instance",
                    Action.UPDATE,
                    before={"backup_retention_period": 7},
                    after={"backup_retention_period": 14},
                )
            )
            == []
        )

    def test_versioning_suspended_flagged(self) -> None:
        [finding] = DurabilityWeakened().check(
            change(
                "aws_s3_bucket_versioning",
                Action.UPDATE,
                before={"versioning_configuration": [{"status": "Enabled"}]},
                after={"versioning_configuration": [{"status": "Suspended"}]},
            )
        )
        assert "versioning" in finding.title.lower()
