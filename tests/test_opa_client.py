"""Testes para o OPA client (fallback e comportamento offline)."""

from pathlib import Path

from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.engine import ActionRequest, PolicyDecision, PolicyEngine, RiskLevel
from governance.policy.opa_client import OpaPolicyEngine

POLICIES_DIR = Path(__file__).parent.parent / "policies"


def make_request(tool: str = "read_files", scopes: list | None = None) -> ActionRequest:
    return ActionRequest(
        agent_id="test",
        agent_name="Test",
        tool_name=tool,
        parameters={},
        environment=AgentEnvironment.DEV,
        scopes=scopes or [AgentScope.READ_FILES],
        risk_level=RiskLevel.LOW,
    )


class TestOpaPolicyEngineOffline:
    def test_fallback_when_opa_offline(self) -> None:
        """Com OPA offline, deve usar o fallback YAML sem erros."""
        engine = OpaPolicyEngine(
            opa_url="http://localhost:19999",  # porta que não existe
            fallback=PolicyEngine(POLICIES_DIR),
            timeout_seconds=0.1,
        )
        result = engine.evaluate(make_request("read_files", [AgentScope.READ_FILES]))
        assert result.decision == PolicyDecision.ALLOW

    def test_fallback_deny_when_no_fallback_and_opa_offline(self) -> None:
        """Sem fallback e OPA offline: fail-closed (DENY)."""
        engine = OpaPolicyEngine(
            opa_url="http://localhost:19999",
            fallback=None,
            timeout_seconds=0.1,
        )
        result = engine.evaluate(make_request())
        assert result.decision == PolicyDecision.DENY
        assert "indisponível" in result.reason

    def test_reload_resets_cache(self) -> None:
        engine = OpaPolicyEngine(
            opa_url="http://localhost:19999",
            fallback=PolicyEngine(POLICIES_DIR),
            timeout_seconds=0.1,
        )
        engine._opa_available = True  # força cache como "disponível"
        engine.reload()
        assert engine._opa_available is None  # cache resetado

    def test_destructive_denied_via_fallback(self) -> None:
        engine = OpaPolicyEngine(
            opa_url="http://localhost:19999",
            fallback=PolicyEngine(POLICIES_DIR),
            timeout_seconds=0.1,
        )
        req = make_request("delete_files", list(AgentScope))
        result = engine.evaluate(req)
        assert result.decision == PolicyDecision.DENY
