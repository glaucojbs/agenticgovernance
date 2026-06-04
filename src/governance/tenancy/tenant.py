"""
Multi-tenancy — isolamento entre equipes/produtos na mesma plataforma.

Cada tenant tem:
  - Seu próprio PolicyEngine (políticas isoladas)
  - Seu próprio BudgetGuard (limites independentes)
  - Seu próprio AgentRegistry (agentes não compartilhados)
  - Seu próprio AuditLogger (trilha de auditoria separada)
  - Um kill switch local (não afeta outros tenants)
  - Um kill switch global (afeta todos — acionado pelo operador da plataforma)

Isolamento garantido:
  - Um agente do tenant A NÃO PODE executar ações em nome do tenant B
  - O budget do tenant A NÃO compartilha limite com o tenant B
  - As políticas do tenant A NÃO afetam decisões do tenant B
  - O kill switch local do tenant A NÃO bloqueia o tenant B
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from governance.approval.gate import ApprovalGate
from governance.audit.logger import AuditLogger
from governance.budget.guard import BudgetConfig, BudgetGuard
from governance.identity.models import AgentIdentity
from governance.policy.engine import PolicyEngine, RiskLevel
from governance.registry.catalog import AgentRegistry, ToolRegistry
from governance.runtime.config import GovernanceConfig
from governance.runtime.governed import ExecutionResult, GovernedAgentRuntime


@dataclass
class TenantConfig:
    """Configuração de um tenant."""
    tenant_id: str
    name: str
    owner: str
    policies_dir: str | Path
    audit_dir: str | Path
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    kill_switch_file: str | None = None
    description: str = ""


class Tenant:
    """
    Contexto isolado de execução para uma equipe ou produto.

    Cada tenant tem seu próprio runtime completamente independente.
    """

    def __init__(
        self,
        config: TenantConfig,
        tool_registry: ToolRegistry,
        governance_config: GovernanceConfig | None = None,
    ) -> None:
        self.config = config
        self._tools = tool_registry

        # Audit isolado por tenant
        audit_path = Path(config.audit_dir) / f"tenant_{config.tenant_id}.jsonl"
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._audit = AuditLogger(audit_path)

        # Kill switch isolado
        ks_file = config.kill_switch_file or f".kill_switch_{config.tenant_id}"
        self._approval = ApprovalGate(
            kill_switch_path=Path(ks_file),
            auto_deny=True,  # padrão; exemplos sobrescrevem
        )

        self._budget = BudgetGuard(config.budget)
        self._agents = AgentRegistry()
        self._policy = PolicyEngine(config.policies_dir)

        gc = governance_config or GovernanceConfig()
        self._runtime = GovernedAgentRuntime(
            policy_engine=self._policy,
            audit_logger=self._audit,
            budget_guard=self._budget,
            approval_gate=self._approval,
            tool_registry=self._tools,
            agent_registry=self._agents,
            timeout_seconds=gc.timeout_seconds,
            telemetry=gc.telemetry,
            anomaly_detector=gc.anomaly_detector,
        )

    @property
    def runtime(self) -> GovernedAgentRuntime:
        return self._runtime

    @property
    def agents(self) -> AgentRegistry:
        return self._agents

    @property
    def audit(self) -> AuditLogger:
        return self._audit

    @property
    def approval(self) -> ApprovalGate:
        return self._approval

    def execute(
        self,
        identity: AgentIdentity,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        risk_level: RiskLevel | None = None,
    ) -> ExecutionResult:
        """
        Executa uma ação no contexto deste tenant.

        Verifica que a identidade pertence a este tenant antes de executar.
        """
        if not self._identity_belongs_to_tenant(identity):
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error=(
                    f"Agente '{identity.id}' não pertence ao tenant "
                    f"'{self.config.tenant_id}' — isolamento violado"
                ),
            )
        return self._runtime.execute(identity, tool_name, parameters, risk_level)

    def _identity_belongs_to_tenant(self, identity: AgentIdentity) -> bool:
        """
        Verifica que o agente está registrado neste tenant.
        Se o agente não está no registry do tenant, bloqueia.
        """
        return self._agents.get(identity.id) is not None

    def register_agent(self, identity: AgentIdentity, auto_approve: bool = False) -> None:
        """Registra um agente neste tenant e emite sua credencial."""
        from governance.registry.catalog import AgentRecord
        record = AgentRecord(
            agent_id=identity.id,
            name=identity.name,
            version=identity.version,
            owner=identity.owner,
            description=f"Tenant: {self.config.tenant_id}",
        )
        self._agents.register(record)
        if auto_approve:
            self._agents.approve(identity.id)
        identity.issue_credential(ttl_seconds=3600)

    def activate_kill_switch(self, reason: str) -> None:
        self._approval.activate_kill_switch(reason)

    def deactivate_kill_switch(self) -> None:
        self._approval.deactivate_kill_switch()

    @property
    def tenant_id(self) -> str:
        return self.config.tenant_id


class TenantRegistry:
    """Catálogo de tenants da plataforma."""

    def __init__(self) -> None:
        self._tenants: dict[str, Tenant] = {}

    def register(self, tenant: Tenant) -> None:
        self._tenants[tenant.tenant_id] = tenant

    def get(self, tenant_id: str) -> Tenant | None:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> list[Tenant]:
        return list(self._tenants.values())

    def __len__(self) -> int:
        return len(self._tenants)


class TenantRuntime:
    """
    Facade que roteia execuções para o tenant correto.

    Garante que nenhum agente de um tenant acesse o runtime de outro.
    """

    def __init__(self, registry: TenantRegistry) -> None:
        self._registry = registry

    def execute_for_tenant(
        self,
        tenant_id: str,
        identity: AgentIdentity,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        risk_level: RiskLevel | None = None,
    ) -> ExecutionResult:
        tenant = self._registry.get(tenant_id)
        if not tenant:
            return ExecutionResult(
                success=False,
                tool_name=tool_name,
                agent_id=identity.id,
                error=f"Tenant '{tenant_id}' não encontrado",
            )
        return tenant.execute(identity, tool_name, parameters, risk_level)

    def activate_global_kill_switch(self, reason: str) -> int:
        """Ativa o kill switch em TODOS os tenants simultaneamente."""
        count = 0
        for tenant in self._registry.list_tenants():
            tenant.activate_kill_switch(f"[GLOBAL] {reason}")
            count += 1
        return count
