"""Testes de isolamento multi-tenant."""

from pathlib import Path

from governance.budget.guard import BudgetConfig
from governance.identity.models import AgentEnvironment, AgentIdentity, AgentScope
from governance.policy.engine import RiskLevel
from governance.registry.catalog import ToolDefinition, ToolRegistry
from governance.tenancy.tenant import (
    Tenant,
    TenantConfig,
    TenantRegistry,
    TenantRuntime,
)

POLICIES_DIR = Path(__file__).parent.parent / "policies"


def _tools():
    tools = ToolRegistry()
    tools.register(
        ToolDefinition(
            name="read_files",
            description="Lê arquivos",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.READ_FILES,
        ),
        implementation=lambda **kw: "ok",
    )
    return tools


def _tenant(tmp_path, tid):
    cfg = TenantConfig(
        tenant_id=tid,
        name=f"Tenant {tid}",
        owner="owner@x.com",
        policies_dir=POLICIES_DIR,
        audit_dir=tmp_path / tid,
        budget=BudgetConfig(max_calls=50),
        kill_switch_file=str(tmp_path / f".ks_{tid}"),
    )
    return Tenant(cfg, _tools())


def _agent(aid):
    return AgentIdentity(
        id=aid,
        name=aid,
        owner="o@x.com",
        environment=AgentEnvironment.DEV,
        scopes=[AgentScope.READ_FILES],
    )


class TestTenant:
    def test_registered_agent_executes(self, tmp_path):
        tenant = _tenant(tmp_path, "a")
        agent = _agent("agent-a")
        tenant.register_agent(agent)
        assert tenant.execute(agent, "read_files", {"path": "/x"}).success

    def test_foreign_agent_blocked(self, tmp_path):
        tenant = _tenant(tmp_path, "a")
        foreign = _agent("agent-b")  # nunca registrado neste tenant
        foreign.issue_credential()
        result = tenant.execute(foreign, "read_files", {"path": "/x"})
        assert not result.success
        assert "isolamento" in result.error

    def test_local_kill_switch(self, tmp_path):
        tenant = _tenant(tmp_path, "a")
        agent = _agent("agent-a")
        tenant.register_agent(agent)
        tenant.activate_kill_switch("manutenção")
        assert not tenant.execute(agent, "read_files").success
        tenant.deactivate_kill_switch()
        assert tenant.execute(agent, "read_files").success


class TestTenantRegistryAndRuntime:
    def test_registry_len_and_get(self, tmp_path):
        reg = TenantRegistry()
        reg.register(_tenant(tmp_path, "a"))
        reg.register(_tenant(tmp_path, "b"))
        assert len(reg) == 2
        assert reg.get("a") is not None
        assert reg.get("zzz") is None

    def test_runtime_routes_to_tenant(self, tmp_path):
        reg = TenantRegistry()
        ta = _tenant(tmp_path, "a")
        reg.register(ta)
        agent = _agent("agent-a")
        ta.register_agent(agent)
        runtime = TenantRuntime(reg)
        assert runtime.execute_for_tenant("a", agent, "read_files", {"p": "/x"}).success

    def test_runtime_unknown_tenant(self, tmp_path):
        runtime = TenantRuntime(TenantRegistry())
        result = runtime.execute_for_tenant("ghost", _agent("x"), "read_files")
        assert not result.success
        assert "não encontrado" in result.error

    def test_global_kill_switch(self, tmp_path):
        reg = TenantRegistry()
        ta, tb = _tenant(tmp_path, "a"), _tenant(tmp_path, "b")
        reg.register(ta)
        reg.register(tb)
        runtime = TenantRuntime(reg)
        count = runtime.activate_global_kill_switch("incidente")
        assert count == 2
        agent = _agent("agent-a")
        ta.register_agent(agent)
        assert not ta.execute(agent, "read_files").success
