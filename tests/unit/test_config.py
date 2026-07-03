from __future__ import annotations

from pathlib import Path

import pytest

from tf_sentry.config import ConfigError, ReviewConfig, load_config
from tf_sentry.models import Severity


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".tf-sentry.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_defaults_without_file() -> None:
    config = load_config(None)
    assert config.fail_on is Severity.HIGH
    assert config.max_deletes == 5
    assert not config.ignore_addresses


def test_full_config_parsed(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
fail_on: critical
ignore:
  - module.legacy.*
rules:
  NET001:
    enabled: false
  IAM004:
    severity: high
blast_radius:
  max_deletes: 10
""",
    )
    config = load_config(path)
    assert config.fail_on is Severity.CRITICAL
    assert config.is_ignored("module.legacy.aws_instance.old")
    assert not config.is_ignored("aws_instance.new")
    assert config.override_for("NET001").enabled is False
    assert config.override_for("IAM004").severity is Severity.HIGH
    assert config.max_deletes == 10


def test_fail_never(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, "fail_on: never"))
    assert config.fail_on is None


def test_unknown_severity_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Unknown severity"):
        load_config(_write(tmp_path, "fail_on: catastrophic"))


def test_malformed_shapes_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="ignore"):
        load_config(_write(tmp_path, "ignore: not-a-list"))
    with pytest.raises(ConfigError, match="max_deletes"):
        load_config(_write(tmp_path, "blast_radius: {max_deletes: 0}"))


def test_rule_ids_case_insensitive(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, "rules: {net001: {enabled: false}}"))
    assert config.override_for("NET001").enabled is False


def test_override_default_is_enabled() -> None:
    assert ReviewConfig().override_for("ANY123").enabled is True
