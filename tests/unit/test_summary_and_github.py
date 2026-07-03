from __future__ import annotations

import httpx
import pytest

from tests.factories import change
from tf_sentry.config import ReviewConfig
from tf_sentry.github import GitHubError, upsert_pr_comment
from tf_sentry.models import Action, Report
from tf_sentry.render.markdown import COMMENT_MARKER
from tf_sentry.rules.engine import run_rules
from tf_sentry.summary.llm import FakeClient, SummaryError, build_client, summarize
from tf_sentry.summary.prompts import SYSTEM_PROMPT, build_user_prompt


def _report() -> Report:
    db = change("aws_db_instance", Action.DELETE, address="aws_db_instance.prod")
    return Report(findings=run_rules([db], ReviewConfig()), changes=[db])


class TestSummary:
    def test_prompt_delimits_untrusted_findings(self) -> None:
        prompt = build_user_prompt(_report())
        assert "BEGIN FINDINGS (untrusted data)" in prompt
        assert "DEL001" in prompt
        assert "untrusted input" in SYSTEM_PROMPT

    def test_prompt_truncates_huge_finding_lists(self) -> None:
        report = _report()
        report.findings = report.findings * 40
        prompt = build_user_prompt(report)
        assert "more findings" in prompt

    def test_fake_client_summarizes(self) -> None:
        text = summarize(_report(), FakeClient())
        assert "review" in text.lower()

    def test_build_client_none_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("TF_SENTRY_LLM_PROVIDER", raising=False)
        assert build_client() is None

    def test_build_client_unknown_provider(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TF_SENTRY_LLM_PROVIDER", "banana")
        with pytest.raises(SummaryError, match="banana"):
            build_client()

    def test_build_client_requires_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TF_SENTRY_LLM_PROVIDER", "openai_compatible")
        monkeypatch.delenv("TF_SENTRY_LLM_MODEL", raising=False)
        with pytest.raises(SummaryError, match="MODEL"):
            build_client()


def _github_transport(existing_comments: list[dict], recorded: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            page = int(dict(request.url.params).get("page", "1"))
            return httpx.Response(200, json=existing_comments if page == 1 else [])
        recorded["method"] = request.method
        recorded["url"] = str(request.url)
        return httpx.Response(200, json={"id": 99})

    return httpx.MockTransport(handler)


class TestGitHubComment:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
        original = httpx.Client

        def patched(**kwargs: object) -> httpx.Client:
            kwargs["transport"] = transport
            return original(**kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(httpx, "Client", patched)

    def test_creates_when_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorded: dict = {}
        self._patch(monkeypatch, _github_transport([], recorded))
        outcome = upsert_pr_comment("body", "o/r", 7, "token")
        assert outcome == "created"
        assert recorded["method"] == "POST"
        assert "/issues/7/comments" in recorded["url"]

    def test_updates_in_place_when_marker_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        existing = [
            {"id": 1, "body": "unrelated comment"},
            {"id": 42, "body": f"{COMMENT_MARKER}\nold report"},
        ]
        recorded: dict = {}
        self._patch(monkeypatch, _github_transport(existing, recorded))
        outcome = upsert_pr_comment("new body", "o/r", 7, "token")
        assert outcome == "updated"
        assert recorded["method"] == "PATCH"
        assert "/comments/42" in recorded["url"]

    def test_permission_error_is_actionable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, json=[])
            return httpx.Response(403, text="forbidden")

        self._patch(monkeypatch, httpx.MockTransport(handler))
        with pytest.raises(GitHubError, match="pull-requests: write"):
            upsert_pr_comment("body", "o/r", 7, "token")

    def test_oversized_body_truncated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, json=[])
            import json as jsonlib

            captured["body"] = jsonlib.loads(request.content)["body"]
            return httpx.Response(200, json={"id": 1})

        self._patch(monkeypatch, httpx.MockTransport(handler))
        upsert_pr_comment("x" * 70000, "o/r", 7, "token")
        assert len(captured["body"]) < 65536
        assert "truncated" in captured["body"]
