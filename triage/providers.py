"""Pluggable LLM providers. All model calls go through LLMProvider.complete().

Providers:
  - StubProvider: deterministic, no network. Used for tests and local dev.
  - OpenAIProvider: live OpenAI chat completions (needs OPENAI_API_KEY).
  - Meta Model API: not a separate class on purpose — the Meta Model API is
    OpenAI-compatible, so it is just OpenAIProvider(base_url=<meta endpoint>,
    api_key=<meta key>). Swapping backends on Oct 26 is a one-liner.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class LLMProvider(ABC):
    @abstractmethod
    def complete(self, system: str, user: str, temperature: float = 0.2) -> str:
        """Return the model's text response for a system+user prompt pair."""
        raise NotImplementedError

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError


class StubProvider(LLMProvider):
    """Deterministic stand-in: keyword-driven responses, no network calls."""

    @property
    def name(self) -> str:
        return "stub"

    def complete(self, system: str, user: str, temperature: float = 0.2) -> str:
        text = (system + "\n" + user).lower()
        if "runbook" in text or "remediat" in text:
            return (
                "RUNBOOK (draft — requires human approval)\n"
                "1. Isolate: revoke the affected credentials / restrict the security group.\n"
                "2. Investigate: pull CloudTrail events for the resource over the incident window.\n"
                "3. Contain: snapshot affected volumes before making changes.\n"
                "4. Remediate: rotate keys, patch the misconfiguration, re-run Config rules.\n"
                "5. Verify: confirm GuardDuty/SecurityHub findings resolve; document in the ticket."
            )
        if "summar" in text:
            return "SUMMARY (stub): correlated findings indicate a single incident requiring review."
        return "STUB RESPONSE: no live model configured. Add an API key to run for real."


class OpenAIProvider(LLMProvider):
    """Live provider via the `openai` package (lazy import — not needed for tests).

    For the Meta Model API (OpenAI-compatible), instantiate as:
        OpenAIProvider(base_url=os.environ["META_MODEL_BASE_URL"],
                       api_key=os.environ["META_MODEL_API_KEY"],
                       model="muse-spark-1.3")
    """

    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 model: str = "gpt-4o-mini"):
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self._base_url = base_url or os.environ.get("OPENAI_BASE_URL", "") or None
        self._model = model

    @property
    def name(self) -> str:
        return f"openai:{self._model}" + (f"@{self._base_url}" if self._base_url else "")

    def complete(self, system: str, user: str, temperature: float = 0.2) -> str:
        try:
            from openai import OpenAI  # lazy: only required for live runs
        except ImportError as exc:
            raise RuntimeError(
                "The 'openai' package is not installed. Run: pip install openai"
            ) from exc
        if not self._api_key:
            raise RuntimeError(
                "No API key set. Export OPENAI_API_KEY (or pass api_key=) first."
            )
        kwargs = {"api_key": self._api_key}
        if self._base_url:
            kwargs["base_url"] = self._base_url
        client = OpenAI(**kwargs)
        resp = client.chat.completions.create(
            model=self._model,
            temperature=temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""


def get_provider(name: str) -> LLMProvider:
    if name == "stub":
        return StubProvider()
    if name == "openai":
        return OpenAIProvider()
    raise ValueError(f"Unknown provider: {name!r} (expected 'stub' or 'openai')")
