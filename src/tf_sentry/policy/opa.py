"""Optional OPA/Rego integration.

Built-in rules cover the universal risks; organizations have policies no
generic tool can know ("no resources outside us-gov-west-1", "every table
tagged with a data classification"). Those belong in Rego, evaluated by
the ``opa`` binary against the same plan JSON.

The adapter shells out to ``opa`` rather than embedding an evaluator:
policy teams already own OPA tooling/testing, and tf-sentry stays free of
a heavyweight dependency. If ``opa`` is not on PATH and a policy dir was
requested, that is a hard error — silently skipping configured policy
would be a security tool lying about coverage.

Policy contract: rules live in package ``tfsentry`` and produce entries in
``deny`` (or ``warn``) shaped as::

    deny contains msg if { ... }              # msg: string, or
    deny contains {"msg": ..., "severity": "high", "address": ...} if { ... }
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from tf_sentry.models import Finding, Severity


class OpaError(RuntimeError):
    """OPA unavailable or evaluation failed."""


def evaluate_rego(plan_json_path: Path, policy_dir: Path) -> list[Finding]:
    opa = shutil.which("opa")
    if opa is None:
        raise OpaError(
            "--rego-dir was provided but the `opa` binary is not on PATH. "
            "Install OPA (https://www.openpolicyagent.org/docs/#running-opa) "
            "or remove the flag."
        )
    if not policy_dir.is_dir():
        raise OpaError(f"Policy directory does not exist: {policy_dir}")

    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [
            opa,
            "eval",
            "--format=json",
            "--input",
            str(plan_json_path),
            "--data",
            str(policy_dir),
            "data.tfsentry",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise OpaError(f"opa eval failed: {result.stderr.strip()[:500]}")

    try:
        payload = json.loads(result.stdout)
        value = payload["result"][0]["expressions"][0]["value"]
    except (json.JSONDecodeError, KeyError, IndexError) as exc:
        raise OpaError(f"Unexpected opa output shape: {result.stdout[:300]}") from exc

    findings: list[Finding] = []
    findings.extend(_to_findings(value.get("deny", []), Severity.HIGH))
    findings.extend(_to_findings(value.get("warn", []), Severity.MEDIUM))
    return findings


def _to_findings(entries: Any, default_severity: Severity) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(entries, list):
        return findings
    for entry in entries:
        if isinstance(entry, str):
            message, severity, address = entry, default_severity, "(rego)"
        elif isinstance(entry, dict):
            message = str(entry.get("msg", "policy violation"))
            severity = (
                Severity.parse(str(entry["severity"]))
                if "severity" in entry
                else default_severity
            )
            address = str(entry.get("address", "(rego)"))
        else:
            continue
        findings.append(
            Finding(
                rule_id="REGO",
                severity=severity,
                address=address,
                title="Organization policy violation",
                detail=message,
                evidence="raised by Rego policy in --rego-dir",
            )
        )
    return findings
