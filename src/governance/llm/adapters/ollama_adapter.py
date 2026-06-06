"""Adapter para modelos locais via Ollama (import preguiçoso)."""

from __future__ import annotations

from typing import Any

from governance.llm.provider import LlmRequest, LlmResponse, LlmUsage

_INSTALL_HINT = "pip install 'agentic-governance[ollama]'"


class OllamaAdapter:
    """Implementa `LlmProvider` sobre o SDK `ollama` (modelos locais)."""

    def __init__(
        self,
        *,
        model: str = "llama3",
        client: Any | None = None,
    ) -> None:
        self._model = model
        self._client = client

    @property
    def name(self) -> str:
        return "ollama"

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import ollama
        except ImportError as exc:  # pragma: no cover - caminho sem SDK
            raise ImportError(f"SDK 'ollama' ausente. Instale com: {_INSTALL_HINT}") from exc
        self._client = ollama
        return self._client

    def complete(self, request: LlmRequest) -> LlmResponse:
        client = self._ensure_client()

        resp = client.chat(
            model=request.model or self._model,
            messages=[{"role": m.role, "content": m.content} for m in request.messages],
            options={"temperature": request.temperature, "num_predict": request.max_tokens},
        )

        # A resposta do Ollama é um mapping (ou objeto com .message).
        message = resp["message"] if isinstance(resp, dict) else resp.message
        content = message["content"] if isinstance(message, dict) else message.content

        def _field(obj: Any, key: str) -> int:
            if isinstance(obj, dict):
                return int(obj.get(key, 0) or 0)
            return int(getattr(obj, key, 0) or 0)

        return LlmResponse(
            text=content or "",
            model=request.model or self._model,
            provider=self.name,
            usage=LlmUsage(
                input_tokens=_field(resp, "prompt_eval_count"),
                output_tokens=_field(resp, "eval_count"),
            ),
            finish_reason="stop",
        )
