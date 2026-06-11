"""
EXEMPLO 07 — Plataforma Multi-Tenant
======================================

Três equipes compartilham a mesma plataforma de governança com
isolamento total: políticas, budgets, agentes e audit logs separados.

Execute: python -m examples.07_multi_tenant
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from examples._shared.setup import POLICIES_DIR, print_header
from governance.budget.guard import BudgetConfig
from governance.identity.models import AgentEnvironment, AgentIdentity, AgentScope
from governance.policy.engine import RiskLevel
from governance.registry.catalog import ToolDefinition, ToolRegistry
from governance.tenancy.tenant import Tenant, TenantConfig, TenantRegistry, TenantRuntime


def make_tool_registry() -> ToolRegistry:
    tools = ToolRegistry()
    for name, risk, scope in [
        ("read_files", RiskLevel.LOW, AgentScope.READ_FILES),
        ("delete_files", RiskLevel.HIGH, AgentScope.DELETE_FILES),
        ("query_database", RiskLevel.LOW, AgentScope.READ_DATABASE),
        ("send_email", RiskLevel.MEDIUM, AgentScope.SEND_EMAIL),
    ]:
        tools.register(
            ToolDefinition(name=name, description=name, risk_level=risk, required_scope=scope),
            implementation=lambda n=name, **kw: f"[SIMULADO] {n}",
        )
    return tools


def run() -> None:
    print_header("EXEMPLO 07 — Plataforma Multi-Tenant")
    print("""
  Cenário: Três equipes (alpha, beta, security) compartilham a plataforma.
  Cada equipe tem políticas, budget e audit log isolados.
  Um agente de alpha NÃO pode executar ações no contexto de beta.
""")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        tools = make_tool_registry()

        # ── Cria tenants ──────────────────────────────────────────────────────
        tenant_registry = TenantRegistry()

        for tenant_id, owner in [
            ("team-alpha", "alice@empresa.com"),
            ("team-beta", "bob@empresa.com"),
            ("security", "sec@empresa.com"),
        ]:
            cfg = TenantConfig(
                tenant_id=tenant_id,
                name=f"Equipe {tenant_id}",
                owner=owner,
                policies_dir=POLICIES_DIR,
                audit_dir=tmp / "audit",
                budget=BudgetConfig(max_calls=20, max_cost_usd=1.0),
                kill_switch_file=str(tmp / f".kill_switch_{tenant_id}"),
            )
            tenant = Tenant(cfg, tools)
            tenant_registry.register(tenant)

        platform = TenantRuntime(tenant_registry)
        print(f"  ✓ Plataforma iniciada com {len(tenant_registry)} tenants\n")

        # ── Cria agentes por tenant ───────────────────────────────────────────
        alpha_tenant = tenant_registry.get("team-alpha")
        beta_tenant = tenant_registry.get("team-beta")

        alpha_agent = AgentIdentity(
            id="alpha-analyst",
            name="AlphaAnalyst",
            owner="alice@empresa.com",
            environment=AgentEnvironment.DEV,
            scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
        )
        beta_agent = AgentIdentity(
            id="beta-analyst",
            name="BetaAnalyst",
            owner="bob@empresa.com",
            environment=AgentEnvironment.DEV,
            scopes=[AgentScope.READ_FILES],
        )

        alpha_tenant.register_agent(alpha_agent, auto_approve=False)
        beta_tenant.register_agent(beta_agent, auto_approve=False)

        # ── Execuções legítimas por tenant ────────────────────────────────────
        print_header("EXECUÇÕES LEGÍTIMAS (cada equipe no seu contexto)")

        r = alpha_tenant.execute(alpha_agent, "read_files", {"path": "/alpha/data"})
        print(f"  alpha → read_files     : {'✓ OK' if r.success else '✗ ' + r.error[:40]}")

        r = beta_tenant.execute(beta_agent, "read_files", {"path": "/beta/reports"})
        print(f"  beta  → read_files     : {'✓ OK' if r.success else '✗ ' + r.error[:40]}")

        # ── Isolamento: agente alpha tentando executar no tenant beta ─────────
        print_header("ISOLAMENTO — Agente de Alpha tentando agir em Beta")

        r = beta_tenant.execute(alpha_agent, "read_files", {"path": "/beta/secret"})
        if not r.success:
            print(f"  ✓ BLOQUEADO: {r.error[:70]}")
        else:
            print("  ✗ FALHA DE ISOLAMENTO: agente alpha acessou beta!")

        # ── Kill switch local (afeta só o tenant alpha) ───────────────────────
        print_header("KILL SWITCH LOCAL — Afeta apenas team-alpha")

        alpha_tenant.activate_kill_switch("manutenção de emergência da equipe alpha")
        print("  Kill switch de alpha ATIVADO")

        r = alpha_tenant.execute(alpha_agent, "read_files")
        print(f"  alpha → read_files     : {'✓ OK' if r.success else '✗ BLOQUEADO (kill switch)'}")

        r = beta_tenant.execute(beta_agent, "read_files")
        print(
            f"  beta  → read_files     : {'✓ OK (não afetado)' if r.success else '✗ ' + r.error[:40]}"
        )

        alpha_tenant.deactivate_kill_switch()
        print("  Kill switch de alpha DESATIVADO")

        # ── Kill switch global (afeta todos) ──────────────────────────────────
        print_header("KILL SWITCH GLOBAL — Afeta TODOS os tenants")

        activated = platform.activate_global_kill_switch("incidente de segurança P0 na plataforma")
        print(f"  Kill switch global ativado em {activated} tenants")

        for t_id, agent in [("team-alpha", alpha_agent), ("team-beta", beta_agent)]:
            r = platform.execute_for_tenant(t_id, agent, "read_files")
            print(f"  {t_id:<12} → {'✓ OK' if r.success else '✗ BLOQUEADO'}")

        # Desativa nos dois tenants
        for t in tenant_registry.list_tenants():
            t.deactivate_kill_switch()
        print("  Kill switches globais DESATIVADOS")

        # ── Budget isolado por tenant ─────────────────────────────────────────
        print_header("BUDGET — Isolado por tenant")

        alpha_budget = alpha_tenant._budget.get_status("alpha-analyst")
        beta_budget = beta_tenant._budget.get_status("beta-analyst")
        print(f"  alpha calls usadas : {alpha_budget.total_calls if alpha_budget else 0}")
        print(f"  beta  calls usadas : {beta_budget.total_calls if beta_budget else 0}")
        print("  (budgets são completamente independentes)")


if __name__ == "__main__":
    run()
