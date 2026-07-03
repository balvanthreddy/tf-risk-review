# ADR-0002: Sensitive values are redacted at the parse boundary

- **Status:** Accepted
- **Date:** 2026-07

## Context

Terraform plan JSON contains full before/after attribute values — including
database passwords, API tokens, and anything else in state. Downstream,
tf-sentry writes findings into PR comments (visible to everyone with repo
read), JSON artifacts (retained by CI), and optionally LLM prompts (sent to
a third party). One careless `evidence=f"{change.after}"` in any future
rule would leak secrets into all three.

Terraform already marks sensitive attributes (`before_sensitive` /
`after_sensitive` mirror the value structure).

## Decision

The parser — the single choke point where plan JSON becomes typed objects —
replaces every value the sensitivity masks flag with `***REDACTED***`
before constructing `ResourceChange`. No rule, renderer, or prompt builder
ever holds an unredacted value; secret hygiene is a property of the type,
not a discipline every contributor must remember.

The detection corpus enforces it: the risky fixture plants a marked
password and asserts it never appears in any finding or change repr.

## Consequences

- Future rules are safe by default; a leak would require deliberately
  re-reading the raw file.
- Trade-off: a rule cannot inspect a sensitive value's *content* (e.g.,
  "password shorter than 12 chars"). Acceptable — judging secrets by value
  in CI is an anti-pattern anyway; that class of check belongs in the
  provider or a secrets scanner.
- Presence remains visible: `sensitive_paths` records *which* attributes
  were sensitive, so rules can still reason about "a secret changed here."
