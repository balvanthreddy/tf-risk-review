"""Optional LLM blast-radius summary.

Strictly advisory by design: the summary can never change the exit code,
never suppress a finding, and is clearly labeled as generated in every
renderer. The LLM receives the *structured findings* (already redacted at
the parse boundary) and change statistics — never raw plan JSON, which
both controls token cost and keeps anything the parser redacted out of
provider hands.

Configuration is environment-driven (works in CI secrets natively):

    TF_RISK_REVIEW_LLM_PROVIDER   openai_compatible | bedrock | fake | none (default)
    TF_RISK_REVIEW_LLM_BASE_URL   e.g. https://api.openai.com/v1
    TF_RISK_REVIEW_LLM_API_KEY
    TF_RISK_REVIEW_LLM_MODEL      e.g. gpt-4o-mini or a Bedrock model id
"""

from __future__ import annotations

import os
from typing import Protocol

import httpx

from tf_risk_review.models import Report
from tf_risk_review.summary.prompts import SYSTEM_PROMPT, build_user_prompt


class SummaryError(RuntimeError):
    """Summary generation failed; the review must proceed without it."""


class SummaryClient(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatibleClient:
    def __init__(self, base_url: str, api_key: str, model: str, timeout: float = 60.0) -> None:
        self._model = model
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout)

    def complete(self, system: str, user: str) -> str:
        try:
            response = self._client.post(
                "/chat/completions",
                json={
                    "model": self._model,
                    "max_tokens": 800,
                    "temperature": 0.0,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                },
            )
            response.raise_for_status()
            return str(response.json()["choices"][0]["message"]["content"])
        except httpx.HTTPError as exc:
            raise SummaryError(f"LLM backend error: {exc}") from exc
        except (KeyError, IndexError, TypeError) as exc:
            raise SummaryError(f"Unexpected LLM response shape: {exc}") from exc


class BedrockClient:
    def __init__(self, model: str) -> None:
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover
            raise SummaryError(
                "Bedrock summary requires `pip install tf-risk-review[bedrock]`"
            ) from exc
        self._model = model
        self._client = boto3.client("bedrock-runtime")

    def complete(self, system: str, user: str) -> str:
        try:
            response = self._client.converse(
                modelId=self._model,
                system=[{"text": system}],
                messages=[{"role": "user", "content": [{"text": user}]}],
                inferenceConfig={"maxTokens": 800, "temperature": 0.0},
            )
            parts = response["output"]["message"]["content"]
            return "".join(part.get("text", "") for part in parts)
        except Exception as exc:
            raise SummaryError(f"Bedrock invocation failed: {exc}") from exc


class FakeClient:
    """Deterministic summary for tests and demos."""

    def complete(self, system: str, user: str) -> str:
        return (
            "This change set includes findings that warrant review before apply. "
            "Prioritize the highest-severity items listed above; verify destructive "
            "changes are intentional and exposure changes are scoped."
        )


def build_client() -> SummaryClient | None:
    provider = os.environ.get("TF_RISK_REVIEW_LLM_PROVIDER", "none").lower()
    if provider in ("none", ""):
        return None
    if provider == "fake":
        return FakeClient()
    if provider == "bedrock":
        model = os.environ.get("TF_RISK_REVIEW_LLM_MODEL", "")
        if not model:
            raise SummaryError("TF_RISK_REVIEW_LLM_MODEL is required for the bedrock provider")
        return BedrockClient(model)
    if provider == "openai_compatible":
        base_url = os.environ.get("TF_RISK_REVIEW_LLM_BASE_URL", "https://api.openai.com/v1")
        model = os.environ.get("TF_RISK_REVIEW_LLM_MODEL", "")
        if not model:
            raise SummaryError("TF_RISK_REVIEW_LLM_MODEL is required for openai_compatible")
        return OpenAICompatibleClient(
            base_url=base_url,
            api_key=os.environ.get("TF_RISK_REVIEW_LLM_API_KEY", ""),
            model=model,
        )
    raise SummaryError(f"Unknown TF_RISK_REVIEW_LLM_PROVIDER: {provider!r}")


def summarize(report: Report, client: SummaryClient) -> str:
    return client.complete(SYSTEM_PROMPT, build_user_prompt(report)).strip()
