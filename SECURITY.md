# Security Policy

## Reporting a vulnerability

Report privately via GitHub Security Advisories ("Report a vulnerability"
on the Security tab), not public issues. Include a reproduction and your
impact assessment; expect an acknowledgment within a few days.

## Threat model summary

**What tf-risk-review protects:** the integrity of the review verdict and the
confidentiality of plan contents.

**Verdict integrity.** Pass/fail comes exclusively from deterministic rules
and Rego policies (ADR-0001). The optional LLM summary has no code path to
findings, severities, or exit codes, so prompt injection via
attacker-controlled resource names/tags is bounded to cosmetic text in an
explicitly labeled advisory section. Configured-but-unavailable OPA is a
hard failure, never a silent skip.

**Plan confidentiality.** Plan JSON can contain secrets from state. Values
Terraform marks sensitive are redacted at the parse boundary (ADR-0002)
before reaching findings, PR comments, JSON artifacts, or LLM prompts; the
test corpus plants a secret and asserts it cannot surface. The LLM (when
enabled) receives structured findings only — never raw plan JSON.

**Residual risks deployers own:**

- Redaction covers what Terraform *marks* sensitive. A secret placed in a
  non-sensitive attribute (e.g., pasted into a `tags` value) is not
  detected here — pair with a secrets scanner.
- The PR comment reveals finding evidence to anyone with repo read access.
  Evidence is designed to be attribute-level, not value-level, but treat
  private-repo hygiene as the boundary.
- `GITHUB_TOKEN` used for comments should be the default workflow token
  with `pull-requests: write` only — the action needs nothing more.
- Rule coverage is a curated list, not a completeness guarantee. tf-risk-review
  reduces reviewer misses; it does not replace review.

## Supported versions

The latest minor release receives security fixes.
