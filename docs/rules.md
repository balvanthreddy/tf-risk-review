# Rule Reference

Severities are defaults; override per repo in `.tf-risk-review.yaml`. Update
actions fire only when the risky attribute actually changed in this plan —
pre-existing conditions are not re-reported on every PR.

## Destructive changes

| ID | Default | Fires when |
|---|---|---|
| `DEL001` | CRITICAL | A stateful resource (databases, buckets, volumes, KMS keys, secrets, log groups — see `STATEFUL_TYPES`) is **deleted** |
| `DEL002` | HIGH | A stateful resource is **replaced** (destroy + create); evidence names the attribute(s) forcing replacement |
| `DEL003` | HIGH | `force_destroy` set to true on buckets/repositories/brokers |
| `DEL004` | HIGH | `deletion_protection` flipped from true to false on an existing resource |
| `DEL900` | HIGH | More than `blast_radius.max_deletes` (default 5) resources destroyed/replaced in one plan |

## IAM privilege widening

| ID | Default | Fires when |
|---|---|---|
| `IAM001` | HIGH (CRITICAL for `*` on `*`) | Allow statements with `Action:*`, write actions on `Resource:*`, or `NotAction` allow-lists — parsed from the policy JSON strings |
| `IAM002` | CRITICAL | Role trust policy allows `Principal:*` (or `AWS:*`) without a Condition |
| `IAM003` | HIGH | AdministratorAccess / PowerUserAccess / IAMFullAccess attached |
| `IAM004` | MEDIUM | Static IAM access key created (long-lived credentials) |

## Network exposure

| ID | Default | Fires when |
|---|---|---|
| `NET001` | HIGH (CRITICAL on sensitive ports) | Security group ingress from `0.0.0.0/0` or `::/0`; escalates when the range covers SSH, RDP, database/search ports, or all traffic |
| `NET002` | HIGH | RDS/Redshift instance set `publicly_accessible = true` |

## Storage risk

| ID | Default | Fires when |
|---|---|---|
| `STO001` | HIGH | S3 public access block flags disabled, or public-read/public-read-write ACLs |
| `STO002` | HIGH | At-rest encryption disabled (RDS, EBS, EFS, Redshift, DynamoDB SSE) |
| `STO003` | MEDIUM | Backup retention reduced or S3 versioning suspended on an existing resource |

## Rego policies

Findings from `--rego-dir` carry rule id `REGO`, default severity HIGH
(`deny`) or MEDIUM (`warn`), overridable per finding by the policy itself.
See [rego.md](rego.md).

## Adding a rule

1. Implement a `ResourceRule` (or `PlanRule`) in `src/tf_risk_review/rules/` —
   pure function of the change, evidence and remediation required.
2. Unit-test positive, negative, and pre-existing-condition paths.
3. Extend the detection corpus: add the triggering resource to a fixture
   (or a new fixture) and pin the expectation in
   `tests/corpus/test_corpus.py`.
4. Document it in this file. Rule IDs are stable API — never reuse one.
