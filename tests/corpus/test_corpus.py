"""Detection corpus: realistic plan fixtures with pinned expectations.

The equivalent of a golden dataset for a detector — every fixture states
exactly which (rule, address) pairs must fire and, implicitly, that
nothing else may. A new rule that fires on the safe fixture, or a
refactor that silences an expected finding, fails here before it ships.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tf_sentry.config import ReviewConfig
from tf_sentry.parser import load_plan
from tf_sentry.rules.engine import run_rules

PLANS = Path(__file__).resolve().parents[2] / "examples" / "plans"

EXPECTATIONS: dict[str, set[tuple[str, str]]] = {
    "safe-change.json": set(),
    "risky-change.json": {
        ("DEL001", "aws_db_instance.orders"),
        ("DEL002", "aws_dynamodb_table.sessions"),
        ("DEL003", "aws_s3_bucket.exports"),
        ("NET001", "aws_security_group.bastion"),
        ("NET002", "aws_db_instance.analytics"),
        ("IAM001", "aws_iam_policy.deploy"),
        ("IAM002", "aws_iam_role.external_integration"),
        ("IAM004", "aws_iam_access_key.reporting_bot"),
        ("STO001", "aws_s3_bucket_public_access_block.reports"),
        ("STO002", "aws_ebs_volume.scratch"),
        ("STO003", "aws_db_instance.analytics"),
    },
    "mass-delete.json": {
        ("DEL900", "(plan-wide)"),
    },
}


@pytest.mark.parametrize("fixture", sorted(EXPECTATIONS))
def test_fixture_detections_exactly_match(fixture: str) -> None:
    changes = load_plan(PLANS / fixture)
    findings = run_rules(changes, ReviewConfig())
    detected = {(f.rule_id, f.address) for f in findings}
    expected = EXPECTATIONS[fixture]

    missed = expected - detected
    unexpected = detected - expected
    assert not missed, f"expected findings not raised: {sorted(missed)}"
    assert not unexpected, f"unexpected findings raised: {sorted(unexpected)}"


def test_risky_fixture_redacts_the_planted_secret() -> None:
    """The fixture plants a password marked sensitive; it must never surface."""
    changes = load_plan(PLANS / "risky-change.json")
    findings = run_rules(changes, ReviewConfig())
    blob = repr(changes) + repr(findings)
    assert "hunter2-should-never-appear" not in blob
    assert "***REDACTED***" in repr(changes)
