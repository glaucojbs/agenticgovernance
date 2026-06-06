"""
OpenTelemetry integration para o runtime de governança.

Emite traces e métricas para cada ação de agente. Suporta:
  - Console exporter (padrão — sem infraestrutura)
  - OTLP exporter (Jaeger/Grafana Tempo em produção)

Configuração via variáveis de ambiente:
  OTEL_EXPORTER=console|otlp        (padrão: console)
  OTEL_ENDPOINT=http://localhost:4318  (para otlp)
  OTEL_SERVICE_NAME=agentic-governance
"""

from __future__ import annotations

import os

from opentelemetry import metrics, trace
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter


def _make_resource() -> Resource:
    return Resource.create({
        "service.name": os.getenv("OTEL_SERVICE_NAME", "agentic-governance"),
        "service.version": "1.0.0",
        "deployment.environment": os.getenv("GOVERNANCE_ENV", "dev"),
    })


class GovernanceTelemetry:
    """
    Singleton de telemetria para o runtime de governança.

    Inicializar uma vez na startup da aplicação:
        telemetry = GovernanceTelemetry.setup()

    Em produção com Jaeger/Tempo:
        OTEL_EXPORTER=otlp OTEL_ENDPOINT=http://jaeger:4318 python ...
    """

    _instance: GovernanceTelemetry | None = None

    def __init__(self, tracer_provider: TracerProvider, meter_provider: MeterProvider) -> None:
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider

        # Tracer — cada execute() vira um span
        self.tracer = tracer_provider.get_tracer("governance.runtime")

        # Meter — contadores e histogramas
        meter = meter_provider.get_meter("governance.metrics")

        # ── Contadores ────────────────────────────────────────────────────────
        self.policy_decisions = meter.create_counter(
            "governance.policy.decisions.total",
            description="Total de decisões de política por resultado",
            unit="1",
        )
        self.actions_executed = meter.create_counter(
            "governance.actions.executed.total",
            description="Total de ações executadas com sucesso",
            unit="1",
        )
        self.actions_denied = meter.create_counter(
            "governance.actions.denied.total",
            description="Total de ações negadas (por motivo)",
            unit="1",
        )
        self.approvals_total = meter.create_counter(
            "governance.approvals.total",
            description="Total de pedidos de aprovação humana",
            unit="1",
        )
        self.budget_exceeded = meter.create_counter(
            "governance.budget.exceeded.total",
            description="Total de vezes que o orçamento foi estourado",
            unit="1",
        )
        self.kill_switch_triggers = meter.create_counter(
            "governance.kill_switch.triggers.total",
            description="Total de bloqueios por kill switch",
            unit="1",
        )

        # ── Contadores Fase 8 (defesas da era agêntica) ───────────────────────
        self.guardrail_blocks = meter.create_counter(
            "governance.guardrail.blocks.total",
            description="Total de bloqueios por guardrails de conteúdo (por direção/regra)",
            unit="1",
        )
        self.tool_integrity_violations = meter.create_counter(
            "governance.tool_integrity.violations.total",
            description="Total de violações de integridade de ferramentas (tool poisoning)",
            unit="1",
        )
        self.memory_quarantines = meter.create_counter(
            "governance.memory.quarantines.total",
            description="Total de entradas de memória colocadas em quarentena",
            unit="1",
        )
        self.a2a_rejections = meter.create_counter(
            "governance.a2a.rejections.total",
            description="Total de mensagens inter-agente rejeitadas",
            unit="1",
        )

        # ── Histogramas ───────────────────────────────────────────────────────
        self.action_latency = meter.create_histogram(
            "governance.action.latency.ms",
            description="Latência de execução de ferramentas em milissegundos",
            unit="ms",
        )
        self.policy_eval_latency = meter.create_histogram(
            "governance.policy.eval.latency.ms",
            description="Latência da avaliação de política em milissegundos",
            unit="ms",
        )

        # ── UpDownCounter (orçamento corrente) ────────────────────────────────
        self.budget_tokens_used = meter.create_up_down_counter(
            "governance.budget.tokens.used",
            description="Tokens consumidos por agente",
            unit="1",
        )
        self.budget_cost_used = meter.create_up_down_counter(
            "governance.budget.cost.used_cents",
            description="Custo acumulado em centavos de dólar",
            unit="1",
        )

    @classmethod
    def setup(cls, export_to_console: bool = True) -> GovernanceTelemetry:
        """Configura e registra os providers globais de trace e métricas."""
        if cls._instance is not None:
            return cls._instance

        resource = _make_resource()
        exporter_type = os.getenv("OTEL_EXPORTER", "console")

        # ── Trace provider ────────────────────────────────────────────────────
        tracer_provider = TracerProvider(resource=resource)

        if exporter_type == "otlp":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            endpoint = os.getenv("OTEL_ENDPOINT", "http://localhost:4318")
            tracer_provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
            )
        else:
            if export_to_console:
                tracer_provider.add_span_processor(
                    BatchSpanProcessor(ConsoleSpanExporter())
                )

        trace.set_tracer_provider(tracer_provider)

        # ── Metrics provider ──────────────────────────────────────────────────
        if exporter_type == "otlp":
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            endpoint = os.getenv("OTEL_ENDPOINT", "http://localhost:4318")
            reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics"),
                export_interval_millis=15_000,
            )
        else:
            reader = PeriodicExportingMetricReader(
                ConsoleMetricExporter(),
                export_interval_millis=60_000,
            )

        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)

        cls._instance = cls(tracer_provider, meter_provider)
        return cls._instance

    @classmethod
    def noop(cls) -> GovernanceTelemetry:
        """Retorna uma instância sem exportação (útil em testes unitários)."""
        if cls._instance is not None:
            return cls._instance
        resource = _make_resource()
        tp = TracerProvider(resource=resource)
        mp = MeterProvider(resource=resource)
        trace.set_tracer_provider(tp)
        metrics.set_meter_provider(mp)
        cls._instance = cls(tp, mp)
        return cls._instance

    def shutdown(self) -> None:
        self._tracer_provider.shutdown()
        self._meter_provider.shutdown()
        GovernanceTelemetry._instance = None


def get_tracer(name: str = "governance.runtime") -> trace.Tracer:
    return trace.get_tracer(name)


def get_meter(name: str = "governance.metrics") -> metrics.Meter:
    return metrics.get_meter(name)


# Atributos padrão para spans
SPAN_ATTR_AGENT_ID = "governance.agent.id"
SPAN_ATTR_AGENT_NAME = "governance.agent.name"
SPAN_ATTR_TOOL_NAME = "governance.tool.name"
SPAN_ATTR_ENVIRONMENT = "governance.environment"
SPAN_ATTR_POLICY_DECISION = "governance.policy.decision"
SPAN_ATTR_RISK_LEVEL = "governance.risk.level"
SPAN_ATTR_DENIED_REASON = "governance.denied.reason"
