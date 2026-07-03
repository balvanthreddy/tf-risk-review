"""Terraform plan JSON parsing.

Input is the output of ``terraform show -json plan.out`` (format_version
1.x). Two responsibilities beyond deserialization:

1. **Action normalization** — the plan encodes a replace as
   ``["delete", "create"]`` (or ``["create", "delete"]`` for
   create_before_destroy); rules should reason about REPLACE, not array
   shapes.
2. **Sensitive-value redaction at the boundary.** Terraform marks
   sensitive attributes in ``before_sensitive``/``after_sensitive``. Those
   values are replaced with a redaction token *before* any rule, renderer,
   or LLM prompt can see them — secret hygiene is enforced structurally,
   not by every downstream consumer remembering to be careful.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tf_sentry.models import Action, ResourceChange

REDACTED = "***REDACTED***"

_SUPPORTED_MAJOR = "1"

_ACTION_MAP: dict[tuple[str, ...], Action] = {
    ("no-op",): Action.NO_OP,
    ("read",): Action.READ,
    ("create",): Action.CREATE,
    ("update",): Action.UPDATE,
    ("delete",): Action.DELETE,
    ("delete", "create"): Action.REPLACE,
    ("create", "delete"): Action.REPLACE,
}


class PlanParseError(ValueError):
    """Raised when the input is not usable Terraform plan JSON."""


def load_plan(path: Path) -> list[ResourceChange]:
    """Load and normalize a plan JSON file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PlanParseError(f"Plan file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise PlanParseError(
            f"{path} is not valid JSON. Generate it with: "
            "terraform plan -out=plan.out && terraform show -json plan.out > plan.json"
        ) from exc
    return parse_plan(raw)


def plan_terraform_version(path: Path) -> str:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    return str(raw.get("terraform_version", ""))


def parse_plan(raw: dict[str, Any]) -> list[ResourceChange]:
    format_version = str(raw.get("format_version", ""))
    if not format_version:
        raise PlanParseError(
            "Input has no format_version — this looks like something other than "
            "`terraform show -json` output (did you pass the binary plan file?)"
        )
    if not format_version.startswith(f"{_SUPPORTED_MAJOR}."):
        raise PlanParseError(f"Unsupported plan format_version {format_version!r}; expected 1.x")

    changes: list[ResourceChange] = []
    for entry in raw.get("resource_changes", []):
        change = entry.get("change", {})
        actions = tuple(change.get("actions", []))
        action = _ACTION_MAP.get(actions)
        if action is None:
            # Future/unknown action shapes must not crash a CI review;
            # treat as UPDATE (the conservative middle) rather than skip.
            action = Action.UPDATE

        sensitive_paths = frozenset(
            _sensitive_paths(change.get("before_sensitive"))
            | _sensitive_paths(change.get("after_sensitive"))
        )

        changes.append(
            ResourceChange(
                address=entry.get("address", ""),
                resource_type=entry.get("type", ""),
                name=entry.get("name", ""),
                provider=entry.get("provider_name", ""),
                action=action,
                before=_redact(change.get("before") or {}, change.get("before_sensitive")),
                after=_redact(change.get("after") or {}, change.get("after_sensitive")),
                after_unknown=change.get("after_unknown") or {},
                sensitive_paths=sensitive_paths,
                replace_paths=tuple(
                    ".".join(str(part) for part in path)
                    for path in change.get("replace_paths", [])
                ),
            )
        )
    return changes


def _redact(value: Any, mask: Any) -> Any:
    """Replace values marked sensitive with a redaction token.

    The mask mirrors the value's structure: ``true`` marks a sensitive
    leaf (or an entire sensitive subtree), dicts/lists mark nested
    structures. Anything the mask flags never reaches rules, reports, or
    prompts.
    """
    if mask is True:
        return REDACTED
    if isinstance(value, dict):
        mask_dict = mask if isinstance(mask, dict) else {}
        return {key: _redact(val, mask_dict.get(key)) for key, val in value.items()}
    if isinstance(value, list):
        mask_list = mask if isinstance(mask, list) else []
        return [
            _redact(item, mask_list[i] if i < len(mask_list) else None)
            for i, item in enumerate(value)
        ]
    return value


def _sensitive_paths(mask: Any, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if mask is True and prefix:
        paths.add(prefix)
    elif isinstance(mask, dict):
        for key, value in mask.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            paths |= _sensitive_paths(value, child)
    elif isinstance(mask, list):
        for i, value in enumerate(mask):
            paths |= _sensitive_paths(value, f"{prefix}[{i}]")
    return paths
