"""Test factories for building normalized resource changes."""

from __future__ import annotations

from typing import Any

from tf_sentry.models import Action, ResourceChange


def change(
    resource_type: str,
    action: Action,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    address: str | None = None,
    replace_paths: tuple[str, ...] = (),
) -> ResourceChange:
    return ResourceChange(
        address=address or f"{resource_type}.test",
        resource_type=resource_type,
        name="test",
        provider="registry.terraform.io/hashicorp/aws",
        action=action,
        before=before or {},
        after=after or {},
        replace_paths=replace_paths,
    )
