# ADR-0001: Deterministic rules gate the build; AI is structurally advisory

- **Status:** Accepted
- **Date:** 2026-07

## Context

The obvious way to build an "AI Terraform reviewer" is to hand the plan to
an LLM and ask "is this risky?" That design has three fatal properties for
a CI gate: it is non-deterministic (same plan, different verdicts), it is
non-auditable ("why did the build fail?" has no stable answer), and it is
attackable (resource names and tags are attacker-controlled input in a
public-repo or compromised-branch scenario — prompt injection can talk a
model into approving anything).

Yet an LLM genuinely adds something rules cannot: a narrative connecting
findings ("these five deletions are one module rename"), which is what a
human reviewer actually wants to read.

## Decision

Two layers with a hard boundary:

1. **Gate layer** — Python rules + optional Rego policies. Pure functions
   of the plan. They produce findings with severity, evidence, and
   remediation, and the severity threshold sets the exit code. Fully
   functional with no AI configured.
2. **Narrative layer** — an optional LLM summary that receives the
   *structured findings* (not the raw plan), is rendered under an explicit
   "AI-generated, advisory only" label, and has no code path by which it
   can alter findings, severities, or the exit code.

The boundary is structural, not procedural: the summarizer's return value
is a string stored in `Report.summary_text`, which no gate logic reads.

## Consequences

- A prompt-injection payload in a resource name can, at worst, produce a
  strange paragraph. It cannot flip a red build green. This bounds the
  blast radius of the entire LLM integration to cosmetics.
- The tool is adoptable by security-conservative teams (the AI is opt-in),
  and the AI cost is zero for the default path.
- Trade-off: the LLM cannot *add* detections. Novel risks that rules miss
  stay missed. That is intentional — a detector whose recall depends on
  model mood is not a detector; new detections are added as rules with
  corpus tests.
