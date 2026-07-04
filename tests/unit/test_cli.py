from __future__ import annotations

import json
from pathlib import Path

import pytest

from tf_risk_review.cli import build_parser, main

PLANS = Path(__file__).resolve().parents[2] / "examples" / "plans"


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    monkeypatch.setattr("sys.argv", ["tf-risk-review", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    return int(exc.value.code or 0)


def test_risky_plan_fails_gate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(monkeypatch, "review", str(PLANS / "risky-change.json"))
    assert code == 1
    out = capsys.readouterr().out
    assert "DEL001" in out
    assert "FAIL" in out


def test_safe_plan_passes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    code = _run(monkeypatch, "review", str(PLANS / "safe-change.json"))
    assert code == 0
    assert "No risks detected" in capsys.readouterr().out


def test_fail_never_reports_but_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    code = _run(monkeypatch, "review", str(PLANS / "risky-change.json"), "--fail-on", "never")
    assert code == 0


def test_json_output_written_to_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    out_file = tmp_path / "reports" / "report.json"
    _run(
        monkeypatch,
        "review",
        str(PLANS / "risky-change.json"),
        "--format",
        "json",
        "--output",
        str(out_file),
    )
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert payload["failed"] is True
    assert any(f["rule_id"] == "IAM002" for f in payload["findings"])


def test_summarize_with_fake_provider(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("TF_RISK_REVIEW_LLM_PROVIDER", "fake")
    _run(monkeypatch, "review", str(PLANS / "risky-change.json"), "--summarize")
    assert "advisory only" in capsys.readouterr().out


def test_bad_plan_is_usage_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("nope", encoding="utf-8")
    assert _run(monkeypatch, "review", str(bad)) == 2
    assert "terraform show -json" in capsys.readouterr().err


def test_missing_opa_with_rego_dir_is_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))  # nothing on PATH
    code = _run(
        monkeypatch,
        "review",
        str(PLANS / "safe-change.json"),
        "--rego-dir",
        str(tmp_path),
    )
    assert code == 2
    assert "opa" in capsys.readouterr().err


def test_config_override_via_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = tmp_path / "cfg.yaml"
    config.write_text("fail_on: never\n", encoding="utf-8")
    # Config says never, flag says high — flag wins.
    code = _run(
        monkeypatch,
        "review",
        str(PLANS / "risky-change.json"),
        "--config",
        str(config),
        "--fail-on",
        "high",
    )
    assert code == 1


def test_parser_rejects_unknown_format() -> None:
    with pytest.raises(SystemExit):
        build_parser().parse_args(["review", "x.json", "--format", "xml"])
