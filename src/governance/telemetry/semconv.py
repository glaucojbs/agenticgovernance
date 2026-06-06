"""
OpenTelemetry GenAI Semantic Conventions (gen_ai.*).

Alinhamento aos atributos padronizados pela OTel GenAI SIG (semconv v1.4x),
falados nativamente por Datadog, Honeycomb, Grafana e por frameworks como
LangChain, CrewAI e AutoGen.

Usamos esses atributos de forma ADITIVA — sem remover os `governance.*` —
para que o runtime seja, ao mesmo tempo, interoperável e específico.

Referência: https://opentelemetry.io/docs/specs/semconv/gen-ai/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from opentelemetry.trace import Span

# Operações (gen_ai.operation.name)
OP_EXECUTE_TOOL = "execute_tool"
OP_INVOKE_AGENT = "invoke_agent"
OP_CREATE_AGENT = "create_agent"

# Atributos padrão gen_ai.*
GEN_AI_SYSTEM = "gen_ai.system"
GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_AGENT_ID = "gen_ai.agent.id"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_TYPE = "gen_ai.tool.type"
GEN_AI_REQUEST_MODEL = "gen_ai.request.model"
GEN_AI_USAGE_INPUT_TOKENS = "gen_ai.usage.input_tokens"
GEN_AI_USAGE_OUTPUT_TOKENS = "gen_ai.usage.output_tokens"
GEN_AI_RESPONSE_FINISH_REASONS = "gen_ai.response.finish_reasons"


def set_tool_span_attributes(
    span: Span,
    *,
    agent_id: str,
    agent_name: str,
    tool_name: str,
    system: str = "agentic-governance",
    model: str | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
    finish_reason: str | None = None,
) -> None:
    """Aplica os atributos gen_ai.* padrão a um span de execução de ferramenta."""
    span.set_attribute(GEN_AI_SYSTEM, system)
    span.set_attribute(GEN_AI_OPERATION_NAME, OP_EXECUTE_TOOL)
    span.set_attribute(GEN_AI_AGENT_ID, agent_id)
    span.set_attribute(GEN_AI_AGENT_NAME, agent_name)
    span.set_attribute(GEN_AI_TOOL_NAME, tool_name)
    span.set_attribute(GEN_AI_TOOL_TYPE, "function")
    if model is not None:
        span.set_attribute(GEN_AI_REQUEST_MODEL, model)
    if input_tokens is not None:
        span.set_attribute(GEN_AI_USAGE_INPUT_TOKENS, input_tokens)
    if output_tokens is not None:
        span.set_attribute(GEN_AI_USAGE_OUTPUT_TOKENS, output_tokens)
    if finish_reason is not None:
        span.set_attribute(GEN_AI_RESPONSE_FINISH_REASONS, [finish_reason])
