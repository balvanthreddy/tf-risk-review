"""Sticky PR comment: create once, update in place on every push.

Uses only the standard GitHub Actions environment (GITHUB_TOKEN,
GITHUB_REPOSITORY, PR number from the event) — no app registration, no
extra secrets.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx

from tf_risk_review.render.markdown import COMMENT_MARKER

_API = "https://api.github.com"
# GitHub caps issue comments at 65536 characters.
_MAX_COMMENT_CHARS = 65000


class GitHubError(RuntimeError):
    """Comment posting failed (auth, permissions, or context)."""


def detect_pr_number() -> int | None:
    """Resolve the PR number from the Actions event payload."""
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).exists():
        return None
    try:
        event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    number = event.get("pull_request", {}).get("number") or event.get("number")
    return int(number) if number else None


def upsert_pr_comment(body: str, repo: str, pr_number: int, token: str) -> str:
    """Create or update the tf-risk-review comment; returns 'created' or 'updated'."""
    if len(body) > _MAX_COMMENT_CHARS:
        body = (
            body[:_MAX_COMMENT_CHARS]
            + "\n\n… *(report truncated — download the JSON artifact for the full list)*"
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    with httpx.Client(base_url=_API, headers=headers, timeout=30.0) as client:
        existing_id = _find_existing(client, repo, pr_number)
        try:
            if existing_id is not None:
                response = client.patch(
                    f"/repos/{repo}/issues/comments/{existing_id}", json={"body": body}
                )
                response.raise_for_status()
                return "updated"
            response = client.post(
                f"/repos/{repo}/issues/{pr_number}/comments", json={"body": body}
            )
            response.raise_for_status()
            return "created"
        except httpx.HTTPStatusError as exc:
            raise GitHubError(
                f"GitHub API returned {exc.response.status_code} — check that the "
                "workflow grants `pull-requests: write` permission. "
                f"Body: {exc.response.text[:300]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise GitHubError(f"GitHub API unreachable: {exc}") from exc


def _find_existing(client: httpx.Client, repo: str, pr_number: int) -> int | None:
    page = 1
    while page <= 10:  # 1000 comments is beyond any sane PR
        response = client.get(
            f"/repos/{repo}/issues/{pr_number}/comments",
            params={"per_page": 100, "page": page},
        )
        response.raise_for_status()
        comments = response.json()
        if not comments:
            return None
        for comment in comments:
            if COMMENT_MARKER in comment.get("body", ""):
                return int(comment["id"])
        page += 1
    return None
