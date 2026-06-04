"""
Catálogo de ferramentas e agentes.

Ferramentas declaram seus metadados de segurança; o runtime consulta o catálogo
antes de permitir que qualquer agente invoque uma ferramenta.

Agentes têm ciclo de vida: registered → approved → deprecated.
Só agentes 'approved' podem operar em 'prod'.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.engine import RiskLevel


class ToolDefinition(BaseModel):
    """Metadados de segurança e governança de uma ferramenta."""

    name: str
    description: str
    risk_level: RiskLevel
    required_scope: AgentScope
    is_destructive: bool = False
    is_reversible: bool = True
    allowed_environments: list[AgentEnvironment] = Field(
        default_factory=lambda: list(AgentEnvironment)
    )
    max_calls_per_session: int | None = None


class AgentStatus(StrEnum):
    REGISTERED = "registered"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


class AgentRecord(BaseModel):
    """Entrada no catálogo de agentes."""

    agent_id: str
    name: str
    version: str
    status: AgentStatus = AgentStatus.REGISTERED
    owner: str
    description: str = ""
    registered_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    approved_at: str | None = None
    deprecated_at: str | None = None
    eval_report: str | None = None  # URL ou referência ao relatório de eval


class ToolRegistry:
    """Catálogo de ferramentas disponíveis no sistema."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}
        # Implementações reais das ferramentas (callables)
        self._implementations: dict[str, Callable[..., Any]] = {}

    def register(
        self,
        definition: ToolDefinition,
        implementation: Callable[..., Any] | None = None,
    ) -> None:
        self._tools[definition.name] = definition
        if implementation:
            self._implementations[definition.name] = implementation

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def get_implementation(self, name: str) -> Callable[..., Any] | None:
        return self._implementations.get(name)

    def list_tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    def is_allowed_in_environment(
        self, tool_name: str, environment: AgentEnvironment
    ) -> bool:
        tool = self._tools.get(tool_name)
        if not tool:
            return False
        return environment in tool.allowed_environments


class AgentRegistry:
    """Catálogo do ciclo de vida dos agentes."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentRecord] = {}

    def register(self, record: AgentRecord) -> AgentRecord:
        if record.agent_id in self._agents:
            raise ValueError(f"Agente '{record.agent_id}' já cadastrado no registry")
        self._agents[record.agent_id] = record
        return record

    def approve(self, agent_id: str, eval_report: str | None = None) -> AgentRecord:
        record = self._get_or_raise(agent_id)
        record.status = AgentStatus.APPROVED
        record.approved_at = datetime.now(UTC).isoformat()
        if eval_report:
            record.eval_report = eval_report
        return record

    def deprecate(self, agent_id: str) -> AgentRecord:
        record = self._get_or_raise(agent_id)
        record.status = AgentStatus.DEPRECATED
        record.deprecated_at = datetime.now(UTC).isoformat()
        return record

    def can_run_in_prod(self, agent_id: str) -> bool:
        """Somente agentes com status APPROVED podem operar em produção."""
        record = self._agents.get(agent_id)
        return record is not None and record.status == AgentStatus.APPROVED

    def get(self, agent_id: str) -> AgentRecord | None:
        return self._agents.get(agent_id)

    def list_agents(self) -> list[AgentRecord]:
        return list(self._agents.values())

    def _get_or_raise(self, agent_id: str) -> AgentRecord:
        record = self._agents.get(agent_id)
        if not record:
            raise ValueError(f"Agente '{agent_id}' não encontrado no registry")
        return record
