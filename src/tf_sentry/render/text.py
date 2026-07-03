"""Plain-text rendering for terminals and CI logs."""

from __future__ import annotations

from tf_sentry.models import Report, Severity


def render_text(report: Report, fail_threshold: Severity | None) -> str:
    lines = ["tf-sentry review", "================", ""]

    actions = report.counts_by_action
    lines.append(
        "Plan: "
        + (
            ", ".join(f"{count} {action}" for action, count in sorted(actions.items()))
            if actions
            else "no resource changes"
        )
    )
    lines.append("")

    if not report.findings:
        lines.append("No risks detected by the enabled rules.")
    else:
        for finding in report.findings:
            lines += [
                f"[{finding.severity}] {finding.rule_id} {finding.address}",
                f"  {finding.title}",
                f"  {finding.detail}",
            ]
            if finding.evidence:
                lines.append(f"  evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"  fix: {finding.remediation}")
            lines.append("")

        counts = ", ".join(f"{sev}: {n}" for sev, n in sorted(report.counts_by_severity.items()))
        lines.append(f"Findings: {counts}")

    if fail_threshold is None:
        lines.append("Gate: review-only (never fails)")
    else:
        status = "FAIL" if report.fails_at(fail_threshold) else "PASS"
        lines.append(f"Gate: fail on {fail_threshold}+ -> {status}")

    if report.summary_text:
        lines += ["", "AI summary (advisory only):", f"  {report.summary_text}"]

    return "\n".join(lines)
