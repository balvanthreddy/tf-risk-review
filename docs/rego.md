# Writing organization policies (OPA/Rego)

Built-in rules cover universal risks. Everything specific to *your*
organization — required tags, approved providers, region restrictions,
naming standards — belongs in Rego, owned by your platform or security
team, versioned in your repo.

## Contract

- Policies live in package **`tf_risk_review`**.
- The **input document** is the full `terraform show -json` output (the
  same file tf-risk-review reviews). Note: values marked sensitive are **not**
  redacted in the OPA input — OPA runs locally against your own file — but
  your policy messages should avoid echoing attribute values verbatim.
- Violations are entries in two sets:
  - `deny` — default severity HIGH
  - `warn` — default severity MEDIUM
- An entry is either a plain string (used as the message) or an object:

```rego
deny contains result if {
    some rc in input.resource_changes
    rc.mode == "managed"
    rc.type == "aws_s3_bucket"
    "create" in rc.change.actions
    not rc.change.after.tags.CostCenter

    result := {
        "msg": sprintf("%s: missing required tag 'CostCenter'", [rc.address]),
        "address": rc.address,       # optional; shown in the report
        "severity": "medium",        # optional; overrides the set default
    }
}
```

Rego findings appear in reports with rule id `REGO` and participate in the
severity gate exactly like built-in findings.

## Running

```bash
tf-risk-review review plan.json --rego-dir policies/
```

Requires the `opa` binary on PATH (in GitHub Actions:
`open-policy-agent/setup-opa@v2`). If `--rego-dir` is set and `opa` is
missing, tf-risk-review exits 2 — configured policy is never silently skipped.

## Testing your policies

Use OPA's native test framework against real plan fixtures:

```bash
opa test policies/ -v
```

Keep a known-bad plan JSON in your repo and assert your policies fire on
it — the same detection-corpus discipline tf-risk-review applies to its
built-in rules (see `tests/corpus/`).

## Working examples

[policies/](../policies) in this repo ships two commented examples:
`required_tags.rego` (create-time tag enforcement) and
`provider_allowlist.rego` (no unapproved providers). Both are
integration-tested in CI against the example plans.
