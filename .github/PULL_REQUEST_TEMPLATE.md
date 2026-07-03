## What & why

<!-- What does this change, and what problem motivates it? Link the issue. -->

## Testing

- [ ] Unit tests cover positive, negative, and quiet paths
- [ ] Detection corpus extended (required for any rule change)
- [ ] `make lint typecheck test` passes locally

## Checklist

- [ ] Rule IDs unchanged (stable API) — new rules get new IDs
- [ ] No path by which the LLM can influence findings or exit codes (ADR-0001)
- [ ] No path around parse-boundary redaction (ADR-0002)
- [ ] docs/rules.md updated if rules changed
- [ ] No new base dependencies (extras are fine)
