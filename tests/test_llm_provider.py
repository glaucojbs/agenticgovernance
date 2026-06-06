"""Testes do contrato neutro de provedor e do MockLlmProvider."""

from __future__ import annotations

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


def _req(text: str = "olá") -> LlmRequest:
    return LlmRequest(model="mock-1", messages=[LlmMessage(role="user", content=text)])


def test_mock_satisfaz_o_protocolo():
    provider = MockLlmProvider()
    assert isinstance(provider, LlmProvider)
    assert provider.name == "mock"


def test_mock_e_deterministico():
    provider = MockLlmProvider()
    r1 = provider.complete(_req("mesma entrada"))
    r2 = MockLlmProvider().complete(_req("mesma entrada"))
    assert r1.text == r2.text
    assert isinstance(r1, LlmResponse)


def test_mock_respostas_roteiradas():
    provider = MockLlmProvider(scripted=["primeira", "segunda"])
    assert provider.complete(_req()).text == "primeira"
    assert provider.complete(_req()).text == "segunda"


def test_mock_responder_callable():
    provider = MockLlmProvider(responder=lambda req: f"eco:{req.messages[-1].content}")
    assert provider.complete(_req("ping")).text == "eco:ping"


def test_mock_reporta_uso_e_provider():
    resp = MockLlmProvider().complete(_req("uma frase qualquer"))
    assert resp.provider == "mock"
    assert resp.usage.input_tokens > 0
    assert resp.usage.output_tokens > 0
    assert resp.usage.total_tokens == resp.usage.input_tokens + resp.usage.output_tokens
    assert resp.finish_reason == "stop"


def test_call_count_incrementa():
    provider = MockLlmProvider()
    provider.complete(_req())
    provider.complete(_req())
    assert provider.call_count == 2


def test_prompt_text_concatena_mensagens():
    req = LlmRequest(
        model="m",
        messages=[
            LlmMessage(role="system", content="sou um sistema"),
            LlmMessage(role="user", content="pergunta"),
        ],
    )
    assert "sou um sistema" in req.prompt_text()
    assert "pergunta" in req.prompt_text()


def test_estimate_tokens():
    assert estimate_tokens("") == 0
    assert estimate_tokens("uma duas tres") == 3


def test_estimate_cost():
    usage = LlmUsage(input_tokens=1000, output_tokens=1000)
    cost = estimate_cost_usd(usage, cost_per_1k_input=0.003, cost_per_1k_output=0.015)
    assert abs(cost - 0.018) < 1e-9
