"""
Provedor de LLM governado.

`GovernedLlmProvider` é um decorator que envolve qualquer `LlmProvider` concreto
e roteia toda inferência pelos controles de governança já existentes — exatamente
como o `GovernedAgentRuntime` faz para execução de ferramentas, mas aplicado à
chamada de inferência em si:

    1. Guardrails de ENTRADA   (prompt injection / DLP no prompt)
    2. Orçamento               (custo, tokens, taxa) — pré-checado e reservado
    3. Inferência              (delega ao provedor interno)
    4. Guardrails de SAÍDA     (vazamento de segredo/PII na resposta)
    5. Telemetria              (span OTel com atributos gen_ai.*)
    6. Auditoria               (evento LLM_INVOKED na cadeia de hash)

Todos os controles são injetados e opcionais: com todos `None`, o wrapper apenas
delega — útil para uso isolado e testes. Nenhum SDK de fornecedor é importado.
"""

from __future__ import annotations

from contextlib import nullcontext

from governance.audit.logger import AuditEventType, AuditLogger
from governance.budget.guard import BudgetExceededError, BudgetGuard
from governance.guardrails.scanner import GuardrailScanner, ScanDirection
from governance.llm.provider import (
    LlmProvider,
    LlmRequest,
    LlmResponse,
    LlmUsage,
    estimate_cost_usd,
    estimate_tokens,
)
from governance.telemetry.semconv import set_llm_span_attributes


class LlmGuardrailError(Exception):
    """Levantada quando um guardrail bloqueia o prompt ou a resposta."""

    def __init__(self, direction: ScanDirection, summary: str) -> None:
        self.direction = direction
        self.summary = summary
        super().__init__(f"Guardrail bloqueou a inferência ({direction.value}): {summary}")


class GovernedLlmProvider:
    """Envolve um `LlmProvider` aplicando os controles de governança."""

    def __init__(
        self,
        provider: LlmProvider,
        *,
        budget: BudgetGuard | None = None,
        guardrails: GuardrailScanner | None = None,
        audit: AuditLogger | None = None,
        tracer: object | None = None,
        cost_per_1k_input: float = 0.003,
        cost_per_1k_output: float = 0.015,
    ) -> None:
        self._provider = provider
        self._budget = budget
        self._guardrails = guardrails
        self._audit = audit
        self._tracer = tracer
        self._cost_in = cost_per_1k_input
        self._cost_out = cost_per_1k_output

    @property
    def name(self) -> str:
        return f"governed:{self._provider.name}"

    def complete(
        self,
        request: LlmRequest,
        *,
        agent_id: str,
        agent_name: str | None = None,
    ) -> LlmResponse:
        """Executa uma inferência governada para um agente identificado."""
        span_cm = (
            self._tracer.start_as_current_span("llm.chat")  # type: ignore[union-attr]
            if self._tracer is not None
            else nullcontext()
        )
        with span_cm as span:
            # 1. Guardrails de entrada — inspeciona o prompt antes de gastar nada.
            if self._guardrails is not None:
                result = self._guardrails.scan_text(request.prompt_text(), ScanDirection.INPUT)
                if result.blocked:
                    self._audit_block(agent_id, agent_name, ScanDirection.INPUT, result.summary())
                    raise LlmGuardrailError(ScanDirection.INPUT, result.summary())

            # 2. Orçamento — pré-checa e reserva com base na estimativa (pior caso).
            est_input = estimate_tokens(request.prompt_text())
            est_total = est_input + request.max_tokens
            if self._budget is not None:
                est_cost = estimate_cost_usd(
                    LlmUsage(input_tokens=est_input, output_tokens=request.max_tokens),
                    cost_per_1k_input=self._cost_in,
                    cost_per_1k_output=self._cost_out,
                )
                try:
                    self._budget.check_and_consume(agent_id, cost_usd=est_cost, tokens=est_total)
                except BudgetExceededError as exc:
                    if self._audit is not None:
                        self._audit.log(
                            AuditEventType.BUDGET_EXCEEDED,
                            agent_id=agent_id,
                            agent_name=agent_name,
                            details={"reason": exc.reason, "stage": "llm"},
                        )
                    raise

            # 3. Inferência — delega ao provedor concreto.
            response = self._provider.complete(request)

            # 4. Guardrails de saída — inspeciona a resposta gerada.
            if self._guardrails is not None:
                out = self._guardrails.scan_text(response.text, ScanDirection.OUTPUT)
                if out.blocked:
                    self._audit_block(agent_id, agent_name, ScanDirection.OUTPUT, out.summary())
                    raise LlmGuardrailError(ScanDirection.OUTPUT, out.summary())

            # 5. Telemetria — atributos gen_ai.* padronizados.
            if span is not None:
                set_llm_span_attributes(
                    span,
                    agent_id=agent_id,
                    model=response.model,
                    provider=response.provider,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    finish_reason=response.finish_reason,
                )

            # 6. Auditoria — registra a inferência na cadeia de hash.
            if self._audit is not None:
                self._audit.log(
                    AuditEventType.LLM_INVOKED,
                    agent_id=agent_id,
                    agent_name=agent_name,
                    details={
                        "provider": response.provider,
                        "model": response.model,
                        "input_tokens": response.usage.input_tokens,
                        "output_tokens": response.usage.output_tokens,
                        "finish_reason": response.finish_reason,
                    },
                )

            return response

    def _audit_block(
        self,
        agent_id: str,
        agent_name: str | None,
        direction: ScanDirection,
        summary: str,
    ) -> None:
        if self._audit is None:
            return
        self._audit.log(
            AuditEventType.GUARDRAIL_BLOCKED,
            agent_id=agent_id,
            agent_name=agent_name,
            details={"direction": direction.value, "summary": summary, "stage": "llm"},
        )
