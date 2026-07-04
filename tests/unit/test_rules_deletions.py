from __future__ import annotations

from tests.factories import change
from tf_risk_review.models import Action, Severity
from tf_risk_review.rules.deletions import (
    BlastRadius,
    DeletionProtectionDisabled,
    ForceDestroyEnabled,
    StatefulDeletion,
    StatefulReplacement,
)


class TestStatefulDeletion:
    def test_flags_database_delete(self) -> None:
        [finding] = StatefulDeletion().check(change("aws_db_instance", Action.DELETE))
        assert finding.rule_id == "DEL001"
        assert finding.severity is Severity.CRITICAL

    def test_ignores_stateless_delete(self) -> None:
        assert StatefulDeletion().check(change("aws_instance", Action.DELETE)) == []

    def test_ignores_stateful_update(self) -> None:
        assert StatefulDeletion().check(change("aws_db_instance", Action.UPDATE)) == []


class TestStatefulReplacement:
    def test_flags_replace_with_forcing_attribute(self) -> None:
        [finding] = StatefulReplacement().check(
            change("aws_dynamodb_table", Action.REPLACE, replace_paths=("name",))
        )
        assert finding.rule_id == "DEL002"
        assert "name" in finding.evidence

    def test_ignores_stateless_replace(self) -> None:
        assert StatefulReplacement().check(change("aws_instance", Action.REPLACE)) == []


class TestForceDestroy:
    def test_flags_newly_enabled(self) -> None:
        [finding] = ForceDestroyEnabled().check(
            change(
                "aws_s3_bucket",
                Action.UPDATE,
                before={"force_destroy": False},
                after={"force_destroy": True},
            )
        )
        assert finding.rule_id == "DEL003"

    def test_silent_when_already_true_and_unchanged(self) -> None:
        # Pre-existing conditions must not spam every subsequent PR.
        assert (
            ForceDestroyEnabled().check(
                change(
                    "aws_s3_bucket",
                    Action.UPDATE,
                    before={"force_destroy": True, "tags": {}},
                    after={"force_destroy": True, "tags": {"a": "b"}},
                )
            )
            == []
        )

    def test_flags_on_create(self) -> None:
        assert ForceDestroyEnabled().check(
            change("aws_s3_bucket", Action.CREATE, after={"force_destroy": True})
        )


class TestDeletionProtectionDisabled:
    def test_flags_true_to_false(self) -> None:
        [finding] = DeletionProtectionDisabled().check(
            change(
                "aws_db_instance",
                Action.UPDATE,
                before={"deletion_protection": True},
                after={"deletion_protection": False},
            )
        )
        assert finding.rule_id == "DEL004"

    def test_ignores_create_without_protection(self) -> None:
        assert (
            DeletionProtectionDisabled().check(
                change("aws_db_instance", Action.CREATE, after={"deletion_protection": False})
            )
            == []
        )


class TestBlastRadius:
    def test_triggers_above_threshold(self) -> None:
        changes = [
            change("aws_instance", Action.DELETE, address=f"aws_instance.w[{i}]") for i in range(6)
        ]
        [finding] = BlastRadius(max_deletes=5).check_plan(changes)
        assert finding.rule_id == "DEL900"
        assert "6 resources" in finding.title

    def test_counts_replaces_as_destruction(self) -> None:
        changes = [
            change("aws_instance", Action.REPLACE, address=f"aws_instance.w[{i}]") for i in range(3)
        ] + [
            change("aws_instance", Action.DELETE, address=f"aws_instance.x[{i}]") for i in range(3)
        ]
        assert BlastRadius(max_deletes=5).check_plan(changes)

    def test_silent_at_threshold(self) -> None:
        changes = [
            change("aws_instance", Action.DELETE, address=f"aws_instance.w[{i}]") for i in range(5)
        ]
        assert BlastRadius(max_deletes=5).check_plan(changes) == []
