# ADR-0003: Built-in rules in Python; org policies via an external OPA adapter

- **Status:** Accepted
- **Date:** 2026-07

## Context

Two kinds of checks exist. Universal risks (deleting a database, `0.0.0.0/0`
on SSH) are true everywhere and benefit from rich evidence extraction —
parsing IAM policy JSON strings, correlating replace_paths. Organizational
policy ("all resources tagged CostCenter", "providers from the approved
list only") varies per company and is owned by platform/security teams who
increasingly standardize on OPA/Rego with their own test tooling
(`opa test`, conftest).

Options considered: everything in Python (org policies become config-file
contortions), everything in Rego (evidence-rich checks like IAM JSON
parsing get painful, and casual users must learn Rego to adopt), or a
split.

## Decision

Split by ownership. Built-in rules are Python classes with unit tests and
corpus coverage — maintained here. Org policies are Rego files in the
consumer's repo, evaluated via `--rego-dir` by shelling out to the `opa`
binary.

Two deliberate details:

- **Shell out, don't embed.** No Python OPA evaluator dependency; policy
  teams run the same `opa` version they test with, and tf-risk-review stays a
  small pure-Python install for the default path.
- **Configured-but-missing OPA is a hard error (exit 2), never a skip.**
  A security gate that silently drops configured policy reports green
  while enforcing nothing — the worst possible failure mode for this
  category of tool.

## Consequences

- Zero-Rego adoption path for most teams; a standard, testable extension
  path for policy teams.
- The Rego contract (package `tf_risk_review`, `deny`/`warn` sets with optional
  severity and address) is documented in docs/rego.md and integration-tested
  in CI with a real `opa` binary.
- Trade-off: Rego findings carry less evidence than built-in rules (the
  policy author controls the message). Acceptable — the policy author is
  also the audience.
