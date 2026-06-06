"""
Contrato neutro de provedor de LLM.

Define as abstrações que o domínio de governança usa para falar com qualquer
modelo de linguagem — `LlmProvider`, `LlmRequest` e `LlmResponse` — sem
depender de nenhum SDK de fornecedor (ver ADR-009).

Adapters concretos (Anthropic, OpenAI, Azure, Ollama, modelos locais) vivem em
`governance.llm.adapters` e importam seus SDKs preguiçosamente; o restante do
sistema enxerga apenas estas estruturas.
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field

Role = Literal["system", "user", "assistant", "tool"]


class LlmMessage(BaseModel):
    """Uma mensagem em uma conversa, neutra a provedor."""

    role: Role
    content: str


class LlmRequest(BaseModel):
    """Pedido de inferência neutro a provedor."""

    model: str
    messages: list[LlmMessage]
    max_tokens: int = 1024
    temperature: float = 0.7
    metadata: dict[str, str] = Field(default_factory=dict)

    def prompt_text(self) -> str:
        """Concatena o conteúdo das mensagens (para varredura de guardrails)."""
        return "\n".join(m.content for m in self.messages)


class LlmUsage(BaseModel):
    """Consumo de tokens reportado por uma inferência."""

    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class LlmResponse(BaseModel):
    """Resposta de inferência neutra a provedor."""

    text: str
    model: str
    provider: str
    usage: LlmUsage = Field(default_factory=LlmUsage)
    finish_reason: str = "stop"


@runtime_checkable
class LlmProvider(Protocol):
    """
    Interface estável que qualquer provedor de LLM deve satisfazer.

    Implementações devem ser puras em relação ao contrato: recebem um
    `LlmRequest` e devolvem um `LlmResponse`. Detalhes de SDK ficam contidos
    no adapter.
    """

    @property
    def name(self) -> str:
        """Identificador curto do provedor (ex.: 'mock', 'anthropic')."""
        ...

    def complete(self, request: LlmRequest) -> LlmResponse:
        """Executa uma inferência e devolve a resposta."""
        ...


# ── Heurísticas de estimativa (offline, sem tokenizer de fornecedor) ──────────


def estimate_tokens(text: str) -> int:
    """
    Estima o número de tokens de um texto sem depender do tokenizer real.

    Aproximação deliberadamente simples e determinística (~1 token por palavra,
    com piso por caracteres) — suficiente para o budget guard pré-checar gastos.
    """
    if not text:
        return 0
    words = len(text.split())
    chars = len(text)
    return max(words, chars // 4, 1)


def estimate_cost_usd(
    usage: LlmUsage,
    *,
    cost_per_1k_input: float = 0.003,
    cost_per_1k_output: float = 0.015,
) -> float:
    """Estima o custo em USD a partir do consumo de tokens (valores simulados)."""
    return (
        usage.input_tokens / 1000.0 * cost_per_1k_input
        + usage.output_tokens / 1000.0 * cost_per_1k_output
    )
