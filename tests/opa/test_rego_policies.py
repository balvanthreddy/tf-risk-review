"""Integration tests for the OPA adapter and the sample Rego policies.

Require the ``opa`` binary (installed in CI via open-policy-agent/setup-opa);
skipped automatically when it is absent locally.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tf_risk_review.models import Severity
from tf_risk_review.policy.opa import OpaError, evaluate_rego

pytestmark = [
    pytest.mark.opa,
    pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not on PATH"),
]

ROOT = Path(__file__).resolve().parents[2]
PLANS = ROOT / "examples" / "plans"
POLICIES = ROOT / "policies"


def test_sample_policies_pass_on_safe_plan() -> None:
    findings = evaluate_rego(PLANS / "safe-change.json", POLICIES)
    # safe-change tags its created EBS volume and uses only approved providers
    assert findings == []


def test_required_tags_policy_fires_on_untagged_create() -> None:
    findings = evaluate_rego(PLANS / "risky-change.json", POLICIES)
    tag_findings = [f for f in findings if "Environment" in f.detail]
    assert tag_findings, "expected required-tags violations on risky fixture"
    assert all(f.rule_id == "REGO" for f in tag_findings)
    assert any(f.severity is Severity.MEDIUM for f in tag_findings)


def test_missing_policy_dir_is_hard_error() -> None:
    with pytest.raises(OpaError, match="does not exist"):
        evaluate_rego(PLANS / "safe-change.json", ROOT / "nonexistent")
