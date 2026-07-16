"""
Minimal multi-provider LLM client interface.

Anthropic is the primary, tested backend for this project. An OpenAI-compatible
adapter is included to show the interface generalizes, but it has not been run
against a live OpenAI/Codex key in this repo - treat it as reference code, not
a verified path, until someone runs it with real credentials.
"""
from __future__ import annotations

import os
from typing import Any


class AnthropicClient:
    """Tested backend - this is what every demo script in this repo actually calls."""

    def __init__(self, model: str = "claude-sonnet-4-5"):
        import anthropic

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("Set ANTHROPIC_API_KEY before running this demo.")
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model

    def create(self, *, system: str, messages: list[dict], max_tokens: int = 2048) -> Any:
        return self._client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )


class OpenAIClient:
    """
    NOT independently verified in this repo - no OpenAI/Codex key was available
    at build time. Included to show the same interface can front either provider.
    """

    def __init__(self, model: str = "gpt-5"):
        import openai  # type: ignore

        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("Set OPENAI_API_KEY before running this demo.")
        self._client = openai.OpenAI(api_key=api_key)
        self.model = model

    def create(self, *, system: str, messages: list[dict], max_tokens: int = 2048) -> Any:
        oa_messages = [{"role": "system", "content": system}] + messages
        return self._client.chat.completions.create(
            model=self.model,
            max_completion_tokens=max_tokens,
            messages=oa_messages,
        )


def get_client(provider: str = "anthropic"):
    if provider == "anthropic":
        return AnthropicClient()
    if provider == "openai":
        return OpenAIClient()
    raise ValueError(f"Unknown provider: {provider}")
