"""
GovernedAgentRuntime — coração do sistema de governança.

Para cada ação que um agente quer executar, na ordem:
  1. Verifica kill switch
  2. Valida identidade e autenticação
  3. Verifica ciclo de vida no registry (prod: apenas agentes approved)
  4. Avalia política (ALLOW / DENY / REQUIRE_APPROVAL)
  5. Verifica orçamento (custo, tokens, calls, rate)
  6. Solicita aprovação humana se necessário
  7. Executa a ferramenta com timeout
  8. Audita TUDO + emite traces/métricas via OpenTelemetry

Este é o único caminho pelo qual um agente pode tocar uma ferramenta.
"""

from __future__ import annotations

import secrets
import threading
import time
from typing import TYPE_CHECKING, Any

from opentelemetry import trace
from opentelemetry.trace import StatusCode
from pydantic import BaseModel

from governance.approval.gate import ApprovalGate, ApprovalRequest, KillSwitchActiveError
from governance.audit.logger import AuditEventType, AuditLogger
from governance.budget.guard import BudgetExceededError, BudgetGuard
from governance.identity.models import AgentEnvironment, AgentIdentity
from governance.policy.engine import ActionRequest, PolicyDecision, PolicyEngine, RiskLevel
from governance.registry.catalog import AgentRegistry, ToolRegistry
from governance.runtime.config import GovernanceConfig
from governance.telemetry.otel import (
    SPAN_ATTR_AGENT_ID,
    SPAN_ATTR_AGENT_NAME,
    SPAN_ATTR_DENIED_REASON,
    SPAN_ATTR_ENVIRONMENT,
    SPAN_ATTR_POLICY_DECISION,
    SPAN_ATTR_RISK_LEVEL,
    SPAN_ATTR_TOOL_NAME,
    GovernanceTelemetry,
)

if TYPE_CHECKING:
    from governance.anomaly.detector import AnomalyDetector
    from governance.circuit_breaker.breaker import CircuitBreakerRegistry
    from governance.masking.masker import PIIMasker


class ExecutionResult(BaseModel):
    """Resultado da execução de uma ferramenta pelo runtime governado."""

    success: bool
    tool_name: str
    agent_id: str
    output: Any | None = None
    error: str | None = None
    policy_decision: str | None = None
    audit_sequence: int | None = None
    trace_id: str | None = None  # ID do span OTEL para correlação


class GovernanceError(Exception):
    """Erro de governança — ação bloqueada pelo runtime."""

    pass


class GovernedAgentRuntime:
    """
    Runtime que envolve toda execução de ferramentas por agentes.

    Aceita opcionalmente um AnomalyDetector e um GovernanceTelemetry.
    Se não fornecidos, opera em modo básico (retrocompatível).
    """

    DEFAULT_TIMEOUT_SECONDS = 30

    def __init__(
        self,
        policy_engine: PolicyEngine,
        audit_logger: AuditLogger,
        budget_guard: BudgetGuard,
        approval_gate: ApprovalGate,
        tool_registry: ToolRegistry,
        agent_registry: AgentRegistry,
        # Parâmetros legados (retro-compatíveis)
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        telemetry: GovernanceTelemetry | None = None,
        anomaly_detector: AnomalyDetector | None = None,
        # Novo: configuração opcional agregada
        config: GovernanceConfig | None = None,
    ) -> None:
        cfg = config or GovernanceConfig()
        self._policy = policy_engine
        self._audit = audit_logger
        self._budget = budget_guard
        self._approval = approval_gate
        self._tools = tool_registry
        self._agents = agent_registry
        # Config tem precedência sobre parâmetros legados
        self._timeout = cfg.timeout_seconds if config else timeout_seconds
        self._tel = cfg.telemetry if config else telemetry
        self._anomaly = cfg.anomaly_detector if config else anomaly_detector
        self._masker: PIIMasker | None = cfg.pii_masker if config else None
        self._cb_registry: CircuitBreakerRegistry | None = cfg.circuit_breakers if config else None

    def execute(
        self,
        identity: AgentIdentity,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        risk_level: RiskLevel | None = None,
    ) -> ExecutionResult:
        """Ponto de entrada único para execução de ferramentas."""
        params = parameters or {}
        start_ms = time.monotonic() * 1000

        tracer = trace.get_tracer("governance.runtime")
        with tracer.start_as_current_span(
            f"governance.execute/{tool_name}",
            kind=trace.SpanKind.INTERNAL,
        ) as span:
            span.set_attribute(SPAN_ATTR_AGENT_ID, identity.id)
            span.set_attribute(SPAN_ATTR_AGENT_NAME, identity.name)
            span.set_attribute(SPAN_ATTR_TOOL_NAME, tool_name)
            span.set_attribute(SPAN_ATTR_ENVIRONMENT, identity.environment.value)

            result = self._execute_inner(identity, tool_name, params, risk_level, span)

            # Métricas de latência
            elapsed_ms = time.monotonic() * 1000 - start_ms
            if self._tel:
                attrs = {
                    "agent.id": identity.id,
                    "tool.name": tool_name,
                    "environment": identity.environment.value,
                    "success": str(result.success),
                }
                self._tel.action_latency.record(elapsed_ms, attrs)

            # Correlação de trace no resultado
            ctx = span.get_span_context()
            if ctx and ctx.is_valid:
                result.trace_id = format(ctx.trace_id, "032x")

            if result.success:
                span.set_status(StatusCode.OK)
            else:
                span.set_status(StatusCode.ERROR, result.error or "governance blocked")
                span.set_attribute(SPAN_ATTR_DENIED_REASON, result.error or "")

            # Anomaly detection pós-execução
            if self._anomaly:
                self._anomaly.observe(identity.id, tool_name, result)

            return result

    def _execute_inner(
        self,
        identity: AgentIdentity,
        tool_name: str,
        params: dict[str, Any],
        risk_level: RiskLevel | None,
        span: trace.Span,
    ) -> ExecutionResult:
        """Lógica central de execução — chamada dentro do span raiz."""

        # Aplica PII masking nos parâmetros antes de qualquer auditoria
        if self._masker and params:
            params = self._masker.mask_details(params)

        # ── 1. Kill switch ────────────────────────────────────────────────────
        try:
            self._approval.check_kill_switch()
        except KillSwitchActiveError as e:
            self._audit.log(
                AuditEventType.KILL_SWITCH_TRIGGERED,
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": str(e)},
            )
            if self._tel:
                self._tel.kill_switch_triggers.add(
                    1, {"agent.id": identity.id, "tool.name": tool_name}
                )
            return ExecutionResult(
                success=False, tool_name=tool_name, agent_id=identity.id,
                error=f"Kill switch ativo: {e}",
            )

        # ── 2. Autenticação ───────────────────────────────────────────────────
        if not identity.is_authenticated():
            self._audit.log(
                AuditEventType.ACTION_DENIED,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": "credencial inválida ou expirada"},
            )
            if self._tel:
                self._tel.actions_denied.add(
                    1, {"agent.id": identity.id, "reason": "invalid_credential"}
                )
            return ExecutionResult(
                success=False, tool_name=tool_name, agent_id=identity.id,
                error="Credencial do agente inválida ou expirada",
            )

        # ── 3. Ciclo de vida no registry ──────────────────────────────────────
        if identity.environment == AgentEnvironment.PROD and not self._agents.can_run_in_prod(
            identity.id
        ):
            record = self._agents.get(identity.id)
            status = record.status.value if record else "não cadastrado"
            self._audit.log(
                AuditEventType.ACTION_DENIED,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": f"agente não aprovado para prod (status: {status})"},
            )
            if self._tel:
                self._tel.actions_denied.add(
                    1, {"agent.id": identity.id, "reason": "not_approved_for_prod"}
                )
            return ExecutionResult(
                success=False, tool_name=tool_name, agent_id=identity.id,
                error=f"Agente com status '{status}' não pode operar em produção",
            )

        # ── 4. Avaliação de política ──────────────────────────────────────────
        tool_def = self._tools.get(tool_name)
        effective_risk = risk_level or (tool_def.risk_level if tool_def else RiskLevel.MEDIUM)
        span.set_attribute(SPAN_ATTR_RISK_LEVEL, effective_risk.value)

        pol_start = time.monotonic() * 1000
        action_request = ActionRequest(
            agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
            parameters=params, environment=identity.environment,
            scopes=identity.scopes, risk_level=effective_risk,
        )
        policy_result = self._policy.evaluate(action_request)
        pol_elapsed = time.monotonic() * 1000 - pol_start

        if self._tel:
            self._tel.policy_eval_latency.record(
                pol_elapsed, {"decision": policy_result.decision.value}
            )
            self._tel.policy_decisions.add(
                1, {"decision": policy_result.decision.value, "tool.name": tool_name}
            )

        span.set_attribute(SPAN_ATTR_POLICY_DECISION, policy_result.decision.value)

        self._audit.log(
            AuditEventType.POLICY_DECISION,
            agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
            environment=identity.environment.value,
            details={
                "decision": policy_result.decision.value,
                "reason": policy_result.reason,
                "matched_rule": policy_result.matched_rule,
                "policy_file": policy_result.policy_file,
            },
        )

        if policy_result.decision == PolicyDecision.DENY:
            event = self._audit.log(
                AuditEventType.ACTION_DENIED,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": policy_result.reason},
            )
            if self._tel:
                self._tel.actions_denied.add(
                    1, {"agent.id": identity.id, "reason": "policy_deny", "tool.name": tool_name}
                )
            return ExecutionResult(
                success=False, tool_name=tool_name, agent_id=identity.id,
                error=f"Negado por política: {policy_result.reason}",
                policy_decision=policy_result.decision.value,
                audit_sequence=event.sequence,
            )

        # ── 5. Verificação de orçamento ───────────────────────────────────────
        try:
            budget_status = self._budget.check_and_consume(identity.id)
            if self._tel:
                self._tel.budget_tokens_used.add(
                    budget_status.total_tokens, {"agent.id": identity.id}
                )
                self._tel.budget_cost_used.add(
                    int(budget_status.total_cost_usd * 100), {"agent.id": identity.id}
                )
        except BudgetExceededError as e:
            event = self._audit.log(
                AuditEventType.BUDGET_EXCEEDED,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": e.reason},
            )
            if self._tel:
                self._tel.budget_exceeded.add(1, {"agent.id": identity.id})
            return ExecutionResult(
                success=False, tool_name=tool_name, agent_id=identity.id,
                error=f"Orçamento excedido: {e.reason}",
                audit_sequence=event.sequence,
            )

        # ── 6. Aprovação humana ───────────────────────────────────────────────
        if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval_req = ApprovalRequest(
                request_id=secrets.token_hex(8),
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                parameters=params, risk_level=effective_risk.value,
                reason=policy_result.reason,
            )
            self._audit.log(
                AuditEventType.APPROVAL_REQUESTED,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"request_id": approval_req.request_id, "reason": policy_result.reason},
            )
            if self._tel:
                self._tel.approvals_total.add(
                    1, {"agent.id": identity.id, "status": "requested"}
                )
            result = self._approval.request_approval(approval_req)

            if result.decision.value == "DENIED":
                event = self._audit.log(
                    AuditEventType.APPROVAL_DENIED,
                    agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                    environment=identity.environment.value,
                    details={"request_id": approval_req.request_id, "notes": result.decision_notes},
                )
                if self._tel:
                    self._tel.approvals_total.add(
                        1, {"agent.id": identity.id, "status": "denied"}
                    )
                return ExecutionResult(
                    success=False, tool_name=tool_name, agent_id=identity.id,
                    error=f"Aprovação negada: {result.decision_notes}",
                    policy_decision="REQUIRE_APPROVAL→DENIED",
                    audit_sequence=event.sequence,
                )

            self._audit.log(
                AuditEventType.APPROVAL_GRANTED,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"request_id": approval_req.request_id, "notes": result.decision_notes},
            )
            if self._tel:
                self._tel.approvals_total.add(
                    1, {"agent.id": identity.id, "status": "granted"}
                )

        # ── 7. Execução com timeout + circuit breaker ─────────────────────────
        if self._cb_registry:
            cb = self._cb_registry.get_or_create(tool_name)
            if cb.state.value == "open":
                event = self._audit.log(
                    AuditEventType.ACTION_DENIED,
                    agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                    environment=identity.environment.value,
                    details={"reason": f"circuit breaker OPEN para '{tool_name}'"},
                )
                return ExecutionResult(
                    success=False, tool_name=tool_name, agent_id=identity.id,
                    error=f"Circuit breaker OPEN — ferramenta '{tool_name}' indisponível",
                    audit_sequence=event.sequence,
                )
        output, exec_error = self._execute_with_timeout(tool_name, params)

        # ── 8. Auditoria do resultado ──────────────────────────────────────────
        if exec_error:
            event = self._audit.log(
                AuditEventType.ERROR,
                agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
                environment=identity.environment.value,
                details={"error": exec_error},
            )
            return ExecutionResult(
                success=False, tool_name=tool_name, agent_id=identity.id,
                error=exec_error, audit_sequence=event.sequence,
            )

        event = self._audit.log(
            AuditEventType.ACTION_EXECUTED,
            agent_id=identity.id, agent_name=identity.name, tool_name=tool_name,
            environment=identity.environment.value,
            details={"parameters": params, "output_preview": str(output)[:200]},
        )
        if self._tel:
            self._tel.actions_executed.add(
                1, {"agent.id": identity.id, "tool.name": tool_name}
            )
        return ExecutionResult(
            success=True, tool_name=tool_name, agent_id=identity.id,
            output=output, policy_decision=policy_result.decision.value,
            audit_sequence=event.sequence,
        )

    def _execute_with_timeout(
        self,
        tool_name: str,
        params: dict[str, Any],
    ) -> tuple[Any, str | None]:
        impl = self._tools.get_implementation(tool_name)
        if not impl:
            return None, f"Ferramenta '{tool_name}' não tem implementação registrada"

        result_holder: list[Any] = [None]
        error_holder: list[str | None] = [None]

        def _run() -> None:
            try:
                result_holder[0] = impl(**params)
            except Exception as e:
                error_holder[0] = str(e)

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        thread.join(timeout=self._timeout)

        if thread.is_alive():
            return None, f"Ferramenta '{tool_name}' excedeu timeout de {self._timeout}s"

        return result_holder[0], error_holder[0]
