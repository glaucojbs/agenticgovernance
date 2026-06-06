"""Adapter para a API Chat Completions da OpenAI (import preguiçoso)."""

from __future__ import annotations

from typing import Any

from governance.llm.provider import LlmRequest, LlmResponse, LlmUsage

_INSTALL_HINT = "pip install 'agentic-governance[openai]'"


class OpenAIAdapter:
    """Implementa `LlmProvider` sobre o SDK `openai`."""

    def __init__(
        self,
        *,
        model: str = "gpt-4o",
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._client = client

    @property
    def name(self) -> str:
        return "openai"

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - caminho sem SDK
            raise ImportError(f"SDK 'openai' ausente. Instale com: {_INSTALL_HINT}") from exc
        self._client = OpenAI(api_key=self._api_key)
        return self._client

    def complete(self, request: LlmRequest) -> LlmResponse:
        client = self._ensure_client()

        resp = client.chat.completions.create(
            model=request.model or self._model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            messages=[{"role": m.role, "content": m.content} for m in request.messages],
        )

        choice = resp.choices[0]
        usage = getattr(resp, "usage", None)
        return LlmResponse(
            text=choice.message.content or "",
            model=getattr(resp, "model", request.model or self._model),
            provider=self.name,
            usage=LlmUsage(
                input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
                output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            ),
            finish_reason=getattr(choice, "finish_reason", "stop") or "stop",
        )
