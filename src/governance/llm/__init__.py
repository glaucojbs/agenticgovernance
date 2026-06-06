"""
Camada LLM-agnóstica de governança.

Materializa o contrato previsto no ADR-009: o domínio depende das abstrações
`LlmProvider`, `LlmRequest` e `LlmResponse`; provedores concretos vivem em
`governance.llm.adapters` (import preguiçoso de SDK). `GovernedLlmProvider`
roteia a inferência pelos controles de governança (orçamento, guardrails,
auditoria, telemetria).
"""

from governance.llm.governed import GovernedLlmProvider, LlmGuardrailError
from governance.llm.mock import MockLlmProvider
from governance.llm.provider import (
    LlmMessage,
    LlmProvider,
    LlmRequest,
    LlmResponse,
    LlmUsage,
    estimate_cost_usd,
    estimate_tokens,
)

__all__ = [
    "LlmProvider",
    "LlmRequest",
    "LlmResponse",
    "LlmMessage",
    "LlmUsage",
    "MockLlmProvider",
    "GovernedLlmProvider",
    "LlmGuardrailError",
    "estimate_tokens",
    "estimate_cost_usd",
]
