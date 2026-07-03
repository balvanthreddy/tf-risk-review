"""Review configuration.

Repos customize behavior with a ``.tf-sentry.yaml`` at the root (or a path
passed via ``--config``). Everything has a working default: zero-config
must produce a useful review, or nobody adopts the action.

```yaml
fail_on: high             # critical | high | medium | low | never
ignore:
  - module.legacy.*       # fnmatch globs on resource addresses
rules:
  NET001:
    enabled: true
    severity: critical    # override the default severity
blast_radius:
  max_deletes: 5          # DEL900 triggers above this
```
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from tf_sentry.models import Severity


class ConfigError(ValueError):
    """Raised for malformed configuration files."""


@dataclass(frozen=True)
class RuleOverride:
    enabled: bool = True
    severity: Severity | None = None


@dataclass
class ReviewConfig:
    fail_on: Severity | None = Severity.HIGH  # None = never fail
    ignore_addresses: list[str] = field(default_factory=list)
    rule_overrides: dict[str, RuleOverride] = field(default_factory=dict)
    max_deletes: int = 5

    def is_ignored(self, address: str) -> bool:
        return any(fnmatch.fnmatch(address, pattern) for pattern in self.ignore_addresses)

    def override_for(self, rule_id: str) -> RuleOverride:
        return self.rule_overrides.get(rule_id, RuleOverride())


def load_config(path: Path | None) -> ReviewConfig:
    if path is None:
        default = Path(".tf-sentry.yaml")
        if not default.exists():
            return ReviewConfig()
        path = default

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path} is not valid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping")

    config = ReviewConfig()

    fail_on = raw.get("fail_on")
    if fail_on is not None:
        config.fail_on = None if str(fail_on).lower() == "never" else Severity.parse(str(fail_on))

    ignore = raw.get("ignore", [])
    if not isinstance(ignore, list):
        raise ConfigError("`ignore` must be a list of address globs")
    config.ignore_addresses = [str(pattern) for pattern in ignore]

    rules = raw.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError("`rules` must be a mapping of rule id to settings")
    for rule_id, settings in rules.items():
        if not isinstance(settings, dict):
            raise ConfigError(f"rules.{rule_id} must be a mapping")
        severity = settings.get("severity")
        config.rule_overrides[str(rule_id).upper()] = RuleOverride(
            enabled=bool(settings.get("enabled", True)),
            severity=Severity.parse(str(severity)) if severity is not None else None,
        )

    blast = raw.get("blast_radius", {})
    if isinstance(blast, dict) and "max_deletes" in blast:
        max_deletes = int(blast["max_deletes"])
        if max_deletes < 1:
            raise ConfigError("blast_radius.max_deletes must be >= 1")
        config.max_deletes = max_deletes

    return config
