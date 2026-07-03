"""Core domain types.

The parser turns raw Terraform plan JSON into these types once; everything
downstream (rules, policies, renderers, the LLM summary) works with typed
objects and never touches raw plan JSON again.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Ordered so thresholds compare naturally (CRITICAL > HIGH > ...)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            valid = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"Unknown severity {value!r}; expected one of: {valid}") from exc

    def __str__(self) -> str:
        return self.name


class Action(IntEnum):
    """Normalized change action, ordered roughly by risk."""

    NO_OP = 0
    READ = 1
    CREATE = 2
    UPDATE = 3
    REPLACE = 4
    DELETE = 5

    def __str__(self) -> str:
        return self.name.lower().replace("_", "-")


@dataclass(frozen=True)
class ResourceChange:
    """One resource's planned change, normalized from plan JSON."""

    address: str
    resource_type: str
    name: str
    provider: str
    action: Action
    before: dict[str, Any] = field(default_factory=dict)
    after: dict[str, Any] = field(default_factory=dict)
    after_unknown: dict[str, Any] = field(default_factory=dict)
    sensitive_paths: frozenset[str] = frozenset()
    replace_paths: tuple[str, ...] = ()

    def before_value(self, *path: str) -> Any:
        return _dig(self.before, path)

    def after_value(self, *path: str) -> Any:
        return _dig(self.after, path)

    def changed(self, *path: str) -> bool:
        return _dig(self.before, path) != _dig(self.after, path)


def _dig(data: Any, path: tuple[str, ...]) -> Any:
    current = data
    for key in path:
        if isinstance(current, list):
            # Terraform models nested blocks as single-element lists.
            current = current[0] if current else None
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


@dataclass(frozen=True)
class Finding:
    """One detected risk, with the evidence to justify it in review."""

    rule_id: str
    severity: Severity
    address: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class Report:
    """The complete result of reviewing one plan."""

    findings: list[Finding]
    changes: list[ResourceChange]
    terraform_version: str = ""
    summary_text: str = ""  # optional LLM narrative, advisory only

    @property
    def max_severity(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.INFO)

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[str(finding.severity)] = counts.get(str(finding.severity), 0) + 1
        return counts

    @property
    def counts_by_action(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for change in self.changes:
            if change.action is not Action.NO_OP and change.action is not Action.READ:
                counts[str(change.action)] = counts.get(str(change.action), 0) + 1
        return counts

    def fails_at(self, threshold: Severity) -> bool:
        return any(f.severity >= threshold for f in self.findings)
