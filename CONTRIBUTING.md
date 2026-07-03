# Contributing

## Setup

```bash
git clone https://github.com/balvanthreddy/tf-sentry && cd tf-sentry
python3 -m venv .venv && source .venv/bin/activate
make install
make test        # OPA tests skip without the opa binary — CI runs them
```

Before opening a PR: `make lint typecheck test`.

## Adding or changing rules

Rules are the product; the bar is correspondingly explicit:

1. **Pure functions only.** A rule sees a `ResourceChange` (or the change
   list) and returns findings. No config reads, no I/O, no globals.
2. **Respect changed-only semantics.** On `UPDATE`, fire only if the risky
   attribute changed in this plan. Pre-existing conditions that re-report
   on every PR train users to ignore the tool.
3. **Evidence and remediation are required.** A finding without evidence
   is an accusation; without remediation it's just bad news.
4. **Tests in both directions.** Positive cases, negative cases, and the
   quiet paths (unchanged attributes, Deny statements, malformed input).
5. **Extend the detection corpus.** Add the triggering resource to an
   example plan and pin the expectation in `tests/corpus/`. The corpus
   asserts exact-match — your rule must not fire on the safe fixture.
6. **Document in docs/rules.md.** Rule IDs are stable API; never reuse or
   renumber.

## Non-negotiables

- Nothing may give the LLM influence over findings or exit codes
  (ADR-0001). PRs that blur this boundary will be declined regardless of
  how useful the feature is.
- Nothing may bypass parse-boundary redaction (ADR-0002).
- No new base dependencies without discussion; optional integrations go
  behind extras.

## Commit style

Conventional prefixes (`feat:`, `fix:`, `docs:`, `test:`, `ci:`, `chore:`);
body explains *why* when it isn't obvious.

## Security issues

Never in public issues — see [SECURITY.md](SECURITY.md).
