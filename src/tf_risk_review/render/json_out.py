"""JSON rendering — the machine-readable artifact for pipelines."""

from __future__ import annotations

import json

from tf_risk_review.models import Report, Severity


def render_json(report: Report, fail_threshold: Severity | None) -> str:
    payload = {
        "version": 1,
        "terraform_version": report.terraform_version,
        "changes": report.counts_by_action,
        "max_severity": str(report.max_severity) if report.findings else None,
        "fail_threshold": str(fail_threshold) if fail_threshold is not None else "never",
        "failed": fail_threshold is not None and report.fails_at(fail_threshold),
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": str(f.severity),
                "address": f.address,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
        "summary_text": report.summary_text or None,
    }
    return json.dumps(payload, indent=2)
