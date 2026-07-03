# Changelog

All notable changes are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[SemVer](https://semver.org/). Rule IDs are stable API.

## [Unreleased]

## [0.1.0] - 2026-07-03

Initial release.

### Added

- Plan parser for `terraform show -json` (format 1.x): action
  normalization (replace folding), nested-block access helpers, and
  sensitive-value redaction at the parse boundary.
- 13 deterministic rules across four families: destructive changes
  (DEL001–DEL004, DEL900 blast radius), IAM privilege widening
  (IAM001–IAM004, parsed from policy JSON strings), network exposure
  (NET001–NET002 with sensitive-port escalation), storage risk
  (STO001–STO003) — all with changed-only semantics on updates.
- Per-repo configuration (`.tf-sentry.yaml`): fail threshold, address
  ignore globs, rule enable/severity overrides, blast-radius tuning.
- Optional OPA/Rego adapter for organization policies with a documented
  contract, working examples, and hard-error semantics when `opa` is
  configured but unavailable.
- Optional advisory AI blast-radius summary (OpenAI-compatible, Bedrock,
  fake providers) — structurally unable to affect pass/fail.
- Renderers: plain text, GitHub-flavored markdown with sticky-comment
  marker, versioned JSON artifact.
- Sticky PR comment upsert using only the default Actions token.
- Reusable composite GitHub Action (`balvanthreddy/tf-sentry@v1`).
- Detection corpus: realistic plan fixtures with exact-match expectations,
  including a planted-secret redaction assertion.
- CI: lint/type/test matrix with 85% coverage gate, OPA integration tests,
  action smoke tests (safe must pass, risky must fail), demo report
  artifact; release workflow with moving major tag.

[Unreleased]: https://github.com/balvanthreddy/tf-sentry/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/balvanthreddy/tf-sentry/releases/tag/v0.1.0
