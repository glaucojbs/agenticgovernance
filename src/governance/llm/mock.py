"""
Provedor de LLM simulado (offline, determinístico).

Permite exercitar toda a camada de governança — testes, exemplos e a suíte de
conformidade — sem rede, sem chave de API e sem nenhum SDK de fornecedor.

A resposta padrão é derivada deterministicamente do prompt. Para testes que
precisam de saídas específicas (ex.: simular vazamento de segredo na saída),
respostas roteiradas podem ser injetadas via fila ou callable.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable

from governance.llm.provider import (
    LlmRequest,
    LlmResponse,
    LlmUsage,
    estimate_tokens,
)


class MockLlmProvider:
    """Implementação de `LlmProvider` puramente local e determinística."""

    def __init__(
        self,
        *,
        responder: Callable[[LlmRequest], str] | None = None,
        scripted: list[str] | None = None,
        model: str = "mock-1",
    ) -> None:
        self._responder = responder
        self._scripted: deque[str] = deque(scripted or [])
        self._model = model
        self.call_count = 0

    @property
    def name(self) -> str:
        return "mock"

    def _render(self, request: LlmRequest) -> str:
        if self._scripted:
            return self._scripted.popleft()
        if self._responder is not None:
            return self._responder(request)
        last = request.messages[-1].content if request.messages else ""
        return f"[mock:{self._model}] resposta determinística para: {last[:120]}"

    def complete(self, request: LlmRequest) -> LlmResponse:
        self.call_count += 1
        text = self._render(request)
        usage = LlmUsage(
            input_tokens=estimate_tokens(request.prompt_text()),
            output_tokens=estimate_tokens(text),
        )
        return LlmResponse(
            text=text,
            model=request.model or self._model,
            provider=self.name,
            usage=usage,
            finish_reason="stop",
        )
