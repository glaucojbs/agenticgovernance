"""Adapter para a API de Messages da Anthropic (import preguiçoso)."""

from __future__ import annotations

from typing import Any

from governance.llm.provider import LlmRequest, LlmResponse, LlmUsage

_INSTALL_HINT = "pip install 'agentic-governance[anthropic]'"


class AnthropicAdapter:
    """Implementa `LlmProvider` sobre o SDK `anthropic`."""

    def __init__(
        self,
        *,
        model: str = "claude-opus-4-8",
        api_key: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._model = model
        self._api_key = api_key
        self._client = client

    @property
    def name(self) -> str:
        return "anthropic"

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - caminho sem SDK
            raise ImportError(f"SDK 'anthropic' ausente. Instale com: {_INSTALL_HINT}") from exc
        self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def complete(self, request: LlmRequest) -> LlmResponse:
        client = self._ensure_client()

        system = "\n".join(m.content for m in request.messages if m.role == "system")
        messages = [
            {"role": m.role, "content": m.content}
            for m in request.messages
            if m.role in ("user", "assistant")
        ]

        resp = client.messages.create(
            model=request.model or self._model,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            system=system or None,
            messages=messages,
        )

        text = "".join(getattr(block, "text", "") for block in resp.content)
        return LlmResponse(
            text=text,
            model=getattr(resp, "model", request.model or self._model),
            provider=self.name,
            usage=LlmUsage(
                input_tokens=getattr(resp.usage, "input_tokens", 0),
                output_tokens=getattr(resp.usage, "output_tokens", 0),
            ),
            finish_reason=getattr(resp, "stop_reason", "stop") or "stop",
        )
