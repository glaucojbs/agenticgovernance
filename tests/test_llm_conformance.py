"""
Suíte de conformidade de adapter.

Qualquer implementação de `LlmProvider` — o mock e cada adapter de fornecedor —
deve satisfazer o mesmo contrato comportamental. Os adapters reais são
exercitados com clientes falsos injetados (sem rede, sem SDK instalado),
garantindo paridade de comportamento entre provedores.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from governance.llm.adapters import (
    AnthropicAdapter,
    AzureOpenAIAdapter,
    OllamaAdapter,
    OpenAIAdapter,
)
from governance.llm.mock import MockLlmProvider
from governance.llm.provider import LlmMessage, LlmProvider, LlmRequest, LlmResponse

# ── Clientes falsos (sem rede) ────────────────────────────────────────────────


class _FakeAnthropic:
    class messages:  # noqa: N801 - espelha a API do SDK
        @staticmethod
        def create(*, model, max_tokens, temperature, system, messages):
            return SimpleNamespace(
                content=[SimpleNamespace(text="resposta anthropic")],
                model=model,
                stop_reason="end_turn",
                usage=SimpleNamespace(input_tokens=11, output_tokens=7),
            )


class _FakeOpenAI:
    class chat:  # noqa: N801
        class completions:  # noqa: N801
            @staticmethod
            def create(*, model, max_tokens, temperature, messages):
                return SimpleNamespace(
                    model=model,
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(content="resposta openai"),
                            finish_reason="stop",
                        )
                    ],
                    usage=SimpleNamespace(prompt_tokens=13, completion_tokens=5),
                )


def _fake_ollama_chat(*, model, messages, options):
    return {
        "message": {"content": "resposta ollama"},
        "prompt_eval_count": 9,
        "eval_count": 4,
    }


_FakeOllama = SimpleNamespace(chat=_fake_ollama_chat)


# ── Factories de provedores conformes ─────────────────────────────────────────

PROVIDER_FACTORIES = {
    "mock": lambda: MockLlmProvider(),
    "anthropic": lambda: AnthropicAdapter(client=_FakeAnthropic()),
    "openai": lambda: OpenAIAdapter(client=_FakeOpenAI()),
    "azure": lambda: AzureOpenAIAdapter(client=_FakeOpenAI()),
    "ollama": lambda: OllamaAdapter(client=_FakeOllama),
}


def _req() -> LlmRequest:
    return LlmRequest(
        model="m-test",
        messages=[
            LlmMessage(role="system", content="seja conciso"),
            LlmMessage(role="user", content="diga olá"),
        ],
        max_tokens=64,
    )


@pytest.mark.parametrize("factory", PROVIDER_FACTORIES.values(), ids=PROVIDER_FACTORIES.keys())
def test_adapter_satisfaz_o_protocolo(factory):
    provider = factory()
    assert isinstance(provider, LlmProvider)
    assert isinstance(provider.name, str) and provider.name


@pytest.mark.parametrize("factory", PROVIDER_FACTORIES.values(), ids=PROVIDER_FACTORIES.keys())
def test_adapter_retorna_resposta_bem_formada(factory):
    provider = factory()
    resp = provider.complete(_req())

    assert isinstance(resp, LlmResponse)
    assert resp.text
    assert resp.model
    assert resp.provider == provider.name
    assert resp.usage.input_tokens >= 0
    assert resp.usage.output_tokens >= 0
    assert resp.finish_reason
