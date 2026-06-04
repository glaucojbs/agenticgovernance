"""Testes para o motor de política."""

from pathlib import Path

import pytest

from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.engine import ActionRequest, PolicyDecision, PolicyEngine, RiskLevel

POLICIES_DIR = Path(__file__).parent.parent / "policies"


def make_request(
    tool_name: str = "read_files",
    scopes: list[AgentScope] | None = None,
    env: AgentEnvironment = AgentEnvironment.DEV,
    risk_level: RiskLevel = RiskLevel.LOW,
    parameters: dict | None = None,
) -> ActionRequest:
    return ActionRequest(
        agent_id="test-agent",
        agent_name="Test Agent",
        tool_name=tool_name,
        parameters=parameters or {},
        environment=env,
        scopes=scopes or [],
        risk_level=risk_level,
    )


@pytest.fixture()
def engine() -> PolicyEngine:
    return PolicyEngine(POLICIES_DIR)


class TestDefaultDeny:
    def test_unknown_tool_is_denied(self, engine: PolicyEngine) -> None:
        req = make_request(tool_name="unknown_tool", scopes=[AgentScope.READ_FILES])
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.DENY
        assert "default-deny" in result.reason

    def test_no_scopes_read_files_denied(self, engine: PolicyEngine) -> None:
        req = make_request(tool_name="read_files", scopes=[])
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.DENY


class TestDestructiveDeny:
    @pytest.mark.parametrize("tool", ["delete_files", "drop_table", "wipe_database"])
    def test_destructive_tools_always_denied(
        self, engine: PolicyEngine, tool: str
    ) -> None:
        req = make_request(
            tool_name=tool,
            scopes=list(AgentScope),
            env=AgentEnvironment.DEV,
            risk_level=RiskLevel.LOW,
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.DENY

    def test_deny_has_precedence_over_allow(self, engine: PolicyEngine) -> None:
        # Mesmo que houvesse uma regra ALLOW para delete_files, DENY tem precedência
        req = make_request(
            tool_name="delete_files",
            scopes=list(AgentScope),
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.DENY


class TestAllowRules:
    def test_read_files_with_correct_scope_allowed(self, engine: PolicyEngine) -> None:
        req = make_request(
            tool_name="read_files",
            scopes=[AgentScope.READ_FILES],
            risk_level=RiskLevel.LOW,
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.ALLOW

    def test_query_database_with_correct_scope_allowed(self, engine: PolicyEngine) -> None:
        req = make_request(
            tool_name="query_database",
            scopes=[AgentScope.READ_DATABASE],
            risk_level=RiskLevel.LOW,
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.ALLOW


class TestRequireApproval:
    def test_high_risk_requires_approval(self, engine: PolicyEngine) -> None:
        req = make_request(
            tool_name="read_files",
            scopes=[AgentScope.READ_FILES],
            risk_level=RiskLevel.HIGH,
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL

    def test_critical_risk_requires_approval(self, engine: PolicyEngine) -> None:
        req = make_request(
            tool_name="call_internal_api",
            scopes=[AgentScope.CALL_INTERNAL_API],
            risk_level=RiskLevel.CRITICAL,
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL

    def test_send_email_in_prod_requires_approval(self, engine: PolicyEngine) -> None:
        req = make_request(
            tool_name="send_email",
            scopes=[AgentScope.SEND_EMAIL],
            env=AgentEnvironment.PROD,
            risk_level=RiskLevel.MEDIUM,
        )
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.REQUIRE_APPROVAL


class TestPolicyReload:
    def test_reload_does_not_crash(self, engine: PolicyEngine) -> None:
        engine.reload()
        req = make_request(tool_name="read_files", scopes=[AgentScope.READ_FILES])
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.ALLOW
