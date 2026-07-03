from __future__ import annotations

import json
from pathlib import Path

import pytest

from tf_sentry.models import Action
from tf_sentry.parser import REDACTED, PlanParseError, load_plan, parse_plan


def _plan(*entries: dict) -> dict:
    return {
        "format_version": "1.2",
        "terraform_version": "1.8.5",
        "resource_changes": list(entries),
    }


def _entry(actions: list[str], **overrides: object) -> dict:
    entry = {
        "address": "aws_s3_bucket.x",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "name": "x",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "change": {
            "actions": actions,
            "before": {},
            "after": {},
            "after_unknown": {},
            "before_sensitive": {},
            "after_sensitive": {},
        },
    }
    entry["change"].update(overrides)  # type: ignore[union-attr]
    return entry


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        (["no-op"], Action.NO_OP),
        (["read"], Action.READ),
        (["create"], Action.CREATE),
        (["update"], Action.UPDATE),
        (["delete"], Action.DELETE),
        (["delete", "create"], Action.REPLACE),
        (["create", "delete"], Action.REPLACE),
        (["some-future-action"], Action.UPDATE),  # conservative fallback
    ],
)
def test_action_normalization(actions: list[str], expected: Action) -> None:
    [change] = parse_plan(_plan(_entry(actions)))
    assert change.action is expected


def test_sensitive_values_redacted_before_anything_sees_them() -> None:
    entry = _entry(
        ["update"],
        before={"password": "old-secret", "engine": "postgres"},
        after={"password": "new-secret", "engine": "postgres", "options": [{"token": "abc"}]},
        before_sensitive={"password": True},
        after_sensitive={"password": True, "options": [{"token": True}]},
    )
    [change] = parse_plan(_plan(entry))
    assert change.before["password"] == REDACTED
    assert change.after["password"] == REDACTED
    assert change.after["options"][0]["token"] == REDACTED
    assert change.after["engine"] == "postgres"
    assert "password" in change.sensitive_paths


def test_replace_paths_flattened() -> None:
    entry = _entry(["delete", "create"], replace_paths=[["name"], ["engine", "version"]])
    [change] = parse_plan(_plan(entry))
    assert change.replace_paths == ("name", "engine.version")


def test_nested_block_access_via_helpers() -> None:
    entry = _entry(
        ["create"],
        after={"versioning_configuration": [{"status": "Enabled"}]},
    )
    [change] = parse_plan(_plan(entry))
    assert change.after_value("versioning_configuration", "status") == "Enabled"
    assert change.after_value("missing", "path") is None


def test_missing_format_version_rejected_with_hint() -> None:
    with pytest.raises(PlanParseError, match="format_version"):
        parse_plan({"resource_changes": []})


def test_unsupported_major_version_rejected() -> None:
    with pytest.raises(PlanParseError, match="format_version"):
        parse_plan({"format_version": "2.0", "resource_changes": []})


def test_load_plan_errors(tmp_path: Path) -> None:
    with pytest.raises(PlanParseError, match="not found"):
        load_plan(tmp_path / "missing.json")

    bad = tmp_path / "bad.json"
    bad.write_text("this is a binary plan, not json", encoding="utf-8")
    with pytest.raises(PlanParseError, match="terraform show -json"):
        load_plan(bad)


def test_empty_plan_yields_no_changes(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"format_version": "1.2"}), encoding="utf-8")
    assert load_plan(path) == []
