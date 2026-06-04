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
  8. Audita TUDO

Este é o único caminho pelo qual um agente pode tocar uma ferramenta.
"""

from __future__ import annotations

import secrets
import threading
from typing import Any

from pydantic import BaseModel

from governance.approval.gate import ApprovalGate, ApprovalRequest, KillSwitchActiveError
from governance.audit.logger import AuditEventType, AuditLogger
from governance.budget.guard import BudgetExceededError, BudgetGuard
from governance.identity.models import AgentEnvironment, AgentIdentity
from governance.policy.engine import ActionRequest, PolicyDecision, PolicyEngine, RiskLevel
from governance.registry.catalog import AgentRegistry, ToolRegistry


class ExecutionResult(BaseModel):
    """Resultado da execução de uma ferramenta pelo runtime governado."""

    success: bool
    tool_name: str
    agent_id: str
    output: Any | None = None
    error: str | None = None
    policy_decision: str | None = None
    audit_sequence: int | None = None


class GovernanceError(Exception):
    """Erro de governança — ação bloqueada pelo runtime."""

    pass


class GovernedAgentRuntime:
    """
    Runtime que envolve toda execução de ferramentas por agentes.

    Configurar uma instância por sessão/contexto de execução.
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
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._policy = policy_engine
        self._audit = audit_logger
        self._budget = budget_guard
        self._approval = approval_gate
        self._tools = tool_registry
        self._agents = agent_registry
        self._timeout = timeout_seconds

    def execute(
        self,
        identity: AgentIdentity,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        risk_level: RiskLevel | None = None,
    ) -> ExecutionResult:
        """
        Ponto de entrada único para execução de ferramentas.

        Todos os controles de governança são aplicados aqui.
        """
        params = parameters or {}

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
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error=f"Kill switch ativo: {e}",
            )

        # ── 2. Autenticação ───────────────────────────────────────────────────
        if not identity.is_authenticated():
            self._audit.log(
                AuditEventType.ACTION_DENIED,
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": "credencial inválida ou expirada"},
            )
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error="Credencial do agente inválida ou expirada",
            )

        # ── 3. Ciclo de vida no registry (prod exige agente approved) ─────────
        if identity.environment == AgentEnvironment.PROD and not self._agents.can_run_in_prod(
            identity.id
        ):
                record = self._agents.get(identity.id)
                status = record.status.value if record else "não cadastrado"
                self._audit.log(
                    AuditEventType.ACTION_DENIED,
                    agent_id=identity.id,
                    agent_name=identity.name,
                    tool_name=tool_name,
                    environment=identity.environment.value,
                    details={"reason": f"agente não aprovado para prod (status: {status})"},
                )
                return ExecutionResult(
                    success=False,
                    tool_name=tool_name,
                    agent_id=identity.id,
                    error=f"Agente com status '{status}' não pode operar em produção",
                )

        # ── 4. Avaliação de política ──────────────────────────────────────────
        tool_def = self._tools.get(tool_name)
        effective_risk = risk_level or (tool_def.risk_level if tool_def else RiskLevel.MEDIUM)

        action_request = ActionRequest(
            agent_id=identity.id,
            agent_name=identity.name,
            tool_name=tool_name,
            parameters=params,
            environment=identity.environment,
            scopes=identity.scopes,
            risk_level=effective_risk,
        )
        policy_result = self._policy.evaluate(action_request)

        self._audit.log(
            AuditEventType.POLICY_DECISION,
            agent_id=identity.id,
            agent_name=identity.name,
            tool_name=tool_name,
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
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": policy_result.reason},
            )
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error=f"Negado por política: {policy_result.reason}",
                policy_decision=policy_result.decision.value,
                audit_sequence=event.sequence,
            )

        # ── 5. Verificação de orçamento ───────────────────────────────────────
        try:
            self._budget.check_and_consume(identity.id)
        except BudgetExceededError as e:
            event = self._audit.log(
                AuditEventType.BUDGET_EXCEEDED,
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={"reason": e.reason},
            )
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error=f"Orçamento excedido: {e.reason}",
                audit_sequence=event.sequence,
            )

        # ── 6. Aprovação humana (se necessário) ───────────────────────────────
        if policy_result.decision == PolicyDecision.REQUIRE_APPROVAL:
            approval_req = ApprovalRequest(
                request_id=secrets.token_hex(8),
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                parameters=params,
                risk_level=effective_risk.value,
                reason=policy_result.reason,
            )
            self._audit.log(
                AuditEventType.APPROVAL_REQUESTED,
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={"request_id": approval_req.request_id, "reason": policy_result.reason},
            )
            result = self._approval.request_approval(approval_req)

            if result.decision.value == "DENIED":
                event = self._audit.log(
                    AuditEventType.APPROVAL_DENIED,
                    agent_id=identity.id,
                    agent_name=identity.name,
                    tool_name=tool_name,
                    environment=identity.environment.value,
                    details={
                        "request_id": approval_req.request_id,
                        "notes": result.decision_notes,
                    },
                )
                return ExecutionResult(
                    success=False,
                    tool_name=tool_name,
                    agent_id=identity.id,
                    error=f"Aprovação negada: {result.decision_notes}",
                    policy_decision="REQUIRE_APPROVAL→DENIED",
                    audit_sequence=event.sequence,
                )

            self._audit.log(
                AuditEventType.APPROVAL_GRANTED,
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={
                    "request_id": approval_req.request_id,
                    "notes": result.decision_notes,
                },
            )

        # ── 7. Execução com timeout ────────────────────────────────────────────
        output, exec_error = self._execute_with_timeout(
            tool_name, params, identity
        )

        # ── 8. Auditoria do resultado ──────────────────────────────────────────
        if exec_error:
            event = self._audit.log(
                AuditEventType.ERROR,
                agent_id=identity.id,
                agent_name=identity.name,
                tool_name=tool_name,
                environment=identity.environment.value,
                details={"error": exec_error},
            )
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error=exec_error,
                audit_sequence=event.sequence,
            )

        event = self._audit.log(
            AuditEventType.ACTION_EXECUTED,
            agent_id=identity.id,
            agent_name=identity.name,
            tool_name=tool_name,
            environment=identity.environment.value,
            details={"parameters": params, "output_preview": str(output)[:200]},
        )
        return ExecutionResult(
            success=True,
            tool_name=tool_name,
            agent_id=identity.id,
            output=output,
            policy_decision=policy_result.decision.value,
            audit_sequence=event.sequence,
        )

    def _execute_with_timeout(
        self,
        tool_name: str,
        params: dict[str, Any],
        identity: AgentIdentity,
    ) -> tuple[Any, str | None]:
        """Executa a ferramenta com timeout via thread."""
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
