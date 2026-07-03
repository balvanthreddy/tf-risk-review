from __future__ import annotations

from tests.factories import change
from tf_sentry.config import ReviewConfig, RuleOverride
from tf_sentry.models import Action, Report, Severity
from tf_sentry.render.json_out import render_json
from tf_sentry.render.markdown import COMMENT_MARKER, render_markdown
from tf_sentry.render.text import render_text
from tf_sentry.rules.engine import run_rules

RISKY_DB_DELETE = change("aws_db_instance", Action.DELETE, address="aws_db_instance.prod")


class TestEngine:
    def test_findings_sorted_by_severity(self) -> None:
        changes = [
            change("aws_iam_access_key", Action.CREATE, after={"user": "x"}),  # MEDIUM
            RISKY_DB_DELETE,  # CRITICAL
        ]
        findings = run_rules(changes, ReviewConfig())
        assert [f.severity for f in findings] == sorted(
            (f.severity for f in findings), reverse=True
        )
        assert findings[0].rule_id == "DEL001"

    def test_ignored_addresses_skipped(self) -> None:
        config = ReviewConfig(ignore_addresses=["aws_db_instance.*"])
        assert run_rules([RISKY_DB_DELETE], config) == []

    def test_disabled_rule_skipped(self) -> None:
        config = ReviewConfig(rule_overrides={"DEL001": RuleOverride(enabled=False)})
        assert run_rules([RISKY_DB_DELETE], config) == []

    def test_severity_override_applied(self) -> None:
        config = ReviewConfig(rule_overrides={"DEL001": RuleOverride(severity=Severity.LOW)})
        [finding] = run_rules([RISKY_DB_DELETE], config)
        assert finding.severity is Severity.LOW

    def test_clean_plan_produces_no_findings(self) -> None:
        clean = change(
            "aws_instance",
            Action.UPDATE,
            before={"instance_type": "t3.medium"},
            after={"instance_type": "t3.large"},
        )
        assert run_rules([clean], ReviewConfig()) == []


def _report() -> Report:
    findings = run_rules([RISKY_DB_DELETE], ReviewConfig())
    return Report(findings=findings, changes=[RISKY_DB_DELETE], terraform_version="1.8.5")


class TestRenderers:
    def test_markdown_contains_marker_and_verdict(self) -> None:
        output = render_markdown(_report(), Severity.HIGH)
        assert output.startswith(COMMENT_MARKER)
        assert "DEL001" in output
        assert "failing" in output
        assert "aws_db_instance.prod" in output

    def test_markdown_passing_without_threshold(self) -> None:
        output = render_markdown(_report(), None)
        assert "review-only" in output

    def test_markdown_escapes_malicious_names(self) -> None:
        report = _report()
        evil = change(
            "aws_db_instance",
            Action.DELETE,
            address="aws_db_instance.<img src=x onerror=alert(1)>",
        )
        from tf_sentry.rules.engine import run_rules as rr

        report.findings = rr([evil], ReviewConfig())
        output = render_markdown(report, Severity.HIGH)
        assert "<img" not in output

    def test_text_shows_gate_status(self) -> None:
        assert "Gate: fail on HIGH+ -> FAIL" in render_text(_report(), Severity.HIGH)
        assert "PASS" in render_text(Report(findings=[], changes=[]), Severity.HIGH)

    def test_json_is_machine_readable(self) -> None:
        import json

        payload = json.loads(render_json(_report(), Severity.HIGH))
        assert payload["failed"] is True
        assert payload["max_severity"] == "CRITICAL"
        assert payload["findings"][0]["rule_id"] == "DEL001"

    def test_ai_summary_labeled_advisory(self) -> None:
        report = _report()
        report.summary_text = "Summary text here."
        markdown = render_markdown(report, Severity.HIGH)
        assert "advisory only" in markdown
        text = render_text(report, Severity.HIGH)
        assert "advisory only" in text
