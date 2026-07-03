"""Rule contracts.

Two kinds of rules:

- :class:`ResourceRule` inspects one resource change at a time — the vast
  majority of checks.
- :class:`PlanRule` sees the whole change set — for aggregate risks like
  blast-radius size that no single resource exhibits.

Rules return findings at their default severity; the engine applies
per-repo overrides. Rules never read configuration directly, so a rule's
behavior is fully determined by its inputs — which is what makes the
detection corpus meaningful.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from tf_sentry.models import Finding, ResourceChange, Severity


class ResourceRule(ABC):
    id: str
    default_severity: Severity

    @abstractmethod
    def check(self, change: ResourceChange) -> list[Finding]:
        """Return findings for one resource change (empty list = clean)."""

    def finding(
        self,
        change: ResourceChange,
        title: str,
        detail: str,
        evidence: str = "",
        remediation: str = "",
    ) -> Finding:
        return Finding(
            rule_id=self.id,
            severity=self.default_severity,
            address=change.address,
            title=title,
            detail=detail,
            evidence=evidence,
            remediation=remediation,
        )


class PlanRule(ABC):
    id: str
    default_severity: Severity

    @abstractmethod
    def check_plan(self, changes: list[ResourceChange]) -> list[Finding]:
        """Return findings computed over the whole change set."""
