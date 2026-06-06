"""Testes do alinhamento às OTel GenAI Semantic Conventions (gen_ai.*)."""

from governance.telemetry import semconv


class _FakeSpan:
    def __init__(self):
        self.attrs = {}

    def set_attribute(self, key, value):
        self.attrs[key] = value


class TestSemConv:
    def test_core_attributes_set(self):
        span = _FakeSpan()
        semconv.set_tool_span_attributes(
            span, agent_id="a-1", agent_name="Analyst", tool_name="read_files"
        )
        assert span.attrs[semconv.GEN_AI_OPERATION_NAME] == semconv.OP_EXECUTE_TOOL
        assert span.attrs[semconv.GEN_AI_AGENT_ID] == "a-1"
        assert span.attrs[semconv.GEN_AI_AGENT_NAME] == "Analyst"
        assert span.attrs[semconv.GEN_AI_TOOL_NAME] == "read_files"
        assert span.attrs[semconv.GEN_AI_SYSTEM] == "agentic-governance"

    def test_optional_attributes_omitted_when_none(self):
        span = _FakeSpan()
        semconv.set_tool_span_attributes(
            span, agent_id="a", agent_name="n", tool_name="t"
        )
        assert semconv.GEN_AI_REQUEST_MODEL not in span.attrs
        assert semconv.GEN_AI_USAGE_INPUT_TOKENS not in span.attrs

    def test_optional_attributes_set_when_provided(self):
        span = _FakeSpan()
        semconv.set_tool_span_attributes(
            span,
            agent_id="a",
            agent_name="n",
            tool_name="t",
            model="claude-opus-4-8",
            input_tokens=10,
            output_tokens=20,
            finish_reason="stop",
        )
        assert span.attrs[semconv.GEN_AI_REQUEST_MODEL] == "claude-opus-4-8"
        assert span.attrs[semconv.GEN_AI_USAGE_INPUT_TOKENS] == 10
        assert span.attrs[semconv.GEN_AI_USAGE_OUTPUT_TOKENS] == 20
        assert span.attrs[semconv.GEN_AI_RESPONSE_FINISH_REASONS] == ["stop"]
