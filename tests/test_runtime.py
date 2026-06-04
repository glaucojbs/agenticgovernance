"""Testes de integração para o GovernedAgentRuntime."""

from pathlib import Path

import pytest

from governance.approval.gate import ApprovalGate
from governance.audit.logger import AuditLogger
from governance.budget.guard import BudgetConfig, BudgetGuard
from governance.identity.models import AgentEnvironment, AgentIdentity, AgentScope
from governance.policy.engine import PolicyEngine, RiskLevel
from governance.registry.catalog import (
    AgentRecord,
    AgentRegistry,
    AgentStatus,
    ToolDefinition,
    ToolRegistry,
)
from governance.runtime.governed import GovernedAgentRuntime

POLICIES_DIR = Path(__file__).parent.parent / "policies"


def build_runtime(
    tmp_path: Path,
    auto_approve: bool = False,
    auto_deny: bool = False,
    budget_config: BudgetConfig | None = None,
) -> tuple[GovernedAgentRuntime, AuditLogger, ApprovalGate]:
    audit = AuditLogger(tmp_path / "audit.jsonl")
    budget = BudgetGuard(budget_config or BudgetConfig())
    approval = ApprovalGate(
        kill_switch_path=tmp_path / ".kill_switch",
        auto_approve=auto_approve,
        auto_deny=auto_deny,
    )
    tool_registry = ToolRegistry()
    tool_registry.register(
        ToolDefinition(
            name="read_files",
            description="Read files",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.READ_FILES,
        ),
        implementation=lambda path="/tmp": f"contents of {path}",
    )
    tool_registry.register(
        ToolDefinition(
            name="delete_files",
            description="Delete files",
            risk_level=RiskLevel.HIGH,
            required_scope=AgentScope.DELETE_FILES,
            is_destructive=True,
        ),
        implementation=lambda path="/tmp": f"deleted {path}",
    )
    tool_registry.register(
        ToolDefinition(
            name="send_email",
            description="Send email",
            risk_level=RiskLevel.MEDIUM,
            required_scope=AgentScope.SEND_EMAIL,
        ),
        implementation=lambda to="", subject="": f"email sent to {to}",
    )

    agent_registry = AgentRegistry()

    runtime = GovernedAgentRuntime(
        policy_engine=PolicyEngine(POLICIES_DIR),
        audit_logger=audit,
        budget_guard=budget,
        approval_gate=approval,
        tool_registry=tool_registry,
        agent_registry=agent_registry,
    )
    return runtime, audit, approval


def make_identity(
    agent_id: str = "agent-001",
    scopes: list[AgentScope] | None = None,
    env: AgentEnvironment = AgentEnvironment.DEV,
) -> AgentIdentity:
    identity = AgentIdentity(
        id=agent_id,
        name="Test Agent",
        owner="owner@example.com",
        environment=env,
        scopes=scopes or [],
    )
    identity.issue_credential()
    return identity


class TestGovernedRuntime:
    def test_allowed_action_succeeds(self, tmp_path: Path) -> None:
        runtime, audit, _ = build_runtime(tmp_path)
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        result = runtime.execute(identity, "read_files", {"path": "/data"})
        assert result.success
        assert result.policy_decision == "ALLOW"

    def test_destructive_tool_denied(self, tmp_path: Path) -> None:
        runtime, audit, _ = build_runtime(tmp_path)
        identity = make_identity(scopes=list(AgentScope))
        result = runtime.execute(identity, "delete_files")
        assert not result.success
        assert "Negado" in result.error

    def test_no_scope_denied(self, tmp_path: Path) -> None:
        runtime, audit, _ = build_runtime(tmp_path)
        identity = make_identity(scopes=[])
        result = runtime.execute(identity, "read_files")
        assert not result.success

    def test_invalid_credential_denied(self, tmp_path: Path) -> None:
        runtime, _, _ = build_runtime(tmp_path)
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        identity.credential = None  # remove credencial
        result = runtime.execute(identity, "read_files")
        assert not result.success
        assert "Credencial" in result.error

    def test_kill_switch_blocks_all(self, tmp_path: Path) -> None:
        runtime, _, approval = build_runtime(tmp_path)
        approval.activate_kill_switch("emergency stop")
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        result = runtime.execute(identity, "read_files")
        assert not result.success
        assert "Kill switch" in result.error

    def test_audit_trail_created(self, tmp_path: Path) -> None:
        runtime, audit, _ = build_runtime(tmp_path)
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        runtime.execute(identity, "read_files")
        events = audit.replay()
        assert len(events) >= 2  # POLICY_DECISION + ACTION_EXECUTED

    def test_audit_chain_valid_after_execution(self, tmp_path: Path) -> None:
        runtime, audit, _ = build_runtime(tmp_path)
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        runtime.execute(identity, "read_files")
        result = audit.verify_chain()
        assert result.valid

    def test_require_approval_auto_approve(self, tmp_path: Path) -> None:
        runtime, _, _ = build_runtime(tmp_path, auto_approve=True)
        identity = make_identity(
            scopes=[AgentScope.READ_FILES],
            env=AgentEnvironment.DEV,
        )
        # Ação de risco HIGH dispara REQUIRE_APPROVAL
        result = runtime.execute(identity, "read_files", risk_level=RiskLevel.HIGH)
        assert result.success

    def test_require_approval_auto_deny(self, tmp_path: Path) -> None:
        runtime, _, _ = build_runtime(tmp_path, auto_deny=True)
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        result = runtime.execute(identity, "read_files", risk_level=RiskLevel.HIGH)
        assert not result.success
        assert "Aprovação negada" in result.error

    def test_budget_exhaustion_blocks(self, tmp_path: Path) -> None:
        config = BudgetConfig(max_calls=1, max_cost_usd=100, max_tokens=100_000)
        runtime, _, _ = build_runtime(tmp_path, budget_config=config)
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        runtime.execute(identity, "read_files")  # usa o orçamento
        result = runtime.execute(identity, "read_files")  # deve falhar
        assert not result.success
        assert "Orçamento" in result.error

    def test_prod_requires_approved_agent(self, tmp_path: Path) -> None:
        runtime, _, _ = build_runtime(tmp_path)
        identity = make_identity(
            scopes=[AgentScope.READ_FILES],
            env=AgentEnvironment.PROD,
        )
        # Agente não está no registry com status APPROVED
        result = runtime.execute(identity, "read_files")
        assert not result.success
        assert "produção" in result.error.lower() or "não aprovado" in result.error.lower()
