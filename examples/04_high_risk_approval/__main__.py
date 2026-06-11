"""
EXEMPLO 04 — Ação de alto risco com aprovação humana e kill switch
==================================================================

Demonstra:
  1. Ação de risco HIGH dispara REQUIRE_APPROVAL → aprovação concedida
  2. A mesma ação → aprovação negada pelo humano
  3. Envio de e-mail em staging exige aprovação (regra específica)
  4. Ativação do kill switch bloqueia TODA execução subsequente
  5. Desativação do kill switch restaura o funcionamento normal

Execute: python -m examples.04_high_risk_approval
"""

from __future__ import annotations

from pathlib import Path

from examples._shared.setup import (
    build_runtime,
    make_identity,
    print_audit_trail,
    print_chain_verification,
    print_header,
    print_result,
)
from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.engine import RiskLevel


def run() -> None:
    print_header("EXEMPLO 04 — Alto Risco, Aprovação Humana e Kill Switch")
    print("""
  Cenário: Um agente de manutenção precisa executar ações de alto risco.
  O runtime pausa e consulta um aprovador humano (simulado) antes de
  prosseguir. Também demonstramos o kill switch de emergência.
""")

    ks_path = Path(".kill_switch_04")
    if ks_path.exists():
        ks_path.unlink()

    # ── Parte 1: Aprovação CONCEDIDA ──────────────────────────────────────────
    print_header("PARTE 1 — Aprovação Concedida pelo Operador")

    runtime_approve, audit_approve, approval_approve, _, _ = build_runtime(
        audit_subdir="04_high_risk_approve",
        auto_approve=True,  # simula operador que aprova
        kill_switch_path=ks_path,
    )

    agent = make_identity(
        agent_id="ops-agent-v1",
        name="OpsAgent",
        owner="bob@empresa.com",
        scopes=[AgentScope.READ_FILES, AgentScope.SEND_EMAIL],
        environment=AgentEnvironment.DEV,
    )

    print("\n  Ação de risco HIGH → requer aprovação → aprovador diz SIM")
    result = runtime_approve.execute(
        agent,
        "read_files",
        {"path": "/prod/config.yaml"},
        risk_level=RiskLevel.HIGH,
    )
    print_result("read_files (HIGH risk) — aprovação CONCEDIDA", result)

    # ── Parte 2: Aprovação NEGADA ─────────────────────────────────────────────
    print_header("PARTE 2 — Aprovação Negada pelo Operador")

    runtime_deny, audit_deny, approval_deny, _, _ = build_runtime(
        audit_subdir="04_high_risk_deny",
        auto_deny=True,  # simula operador que nega
        kill_switch_path=ks_path,
    )

    print("\n  A mesma ação de risco HIGH → aprovador diz NÃO")
    result = runtime_deny.execute(
        agent,
        "read_files",
        {"path": "/prod/config.yaml"},
        risk_level=RiskLevel.HIGH,
    )
    print_result("read_files (HIGH risk) — aprovação NEGADA", result)

    # ── Parte 3: E-mail em staging → aprovação via callback ───────────────────
    print_header("PARTE 3 — E-mail em Staging com Aprovação via Callback")

    approval_history: list[str] = []

    def human_callback(req):
        msg = (
            f"  👤 [OPERADOR SIMULADO] Pedido de aprovação recebido:\n"
            f"     Agente   : {req.agent_name}\n"
            f"     Ferramenta: {req.tool_name}\n"
            f"     Risco    : {req.risk_level}\n"
            f"     Motivo   : {req.reason}\n"
            f"     Parâmetros: {req.parameters}\n"
            f"  👤 [OPERADOR SIMULADO] Decisão: APROVADO (ambiente de staging verificado)"
        )
        print(msg)
        approval_history.append(req.request_id)
        return True, "aprovado pelo operador após verificação do ambiente"

    staging_agent = make_identity(
        agent_id="notifier-staging-v1",
        name="NotifierAgent",
        owner="carol@empresa.com",
        scopes=[AgentScope.SEND_EMAIL],
        environment=AgentEnvironment.STAGING,
    )

    runtime_staging, audit_staging, _, _, _ = build_runtime(
        audit_subdir="04_staging_email",
        approver_callback=human_callback,
        kill_switch_path=ks_path,
    )

    result = runtime_staging.execute(
        staging_agent,
        "send_email",
        {"to": "users@empresa.com", "subject": "Manutenção programada"},
    )
    print_result("send_email (staging) — callback do operador", result)
    print(f"\n  Aprovações registradas via callback: {len(approval_history)}")

    # ── Parte 4: Kill switch ──────────────────────────────────────────────────
    print_header("PARTE 4 — Kill Switch Global de Emergência")

    runtime_ks, audit_ks, approval_ks, _, _ = build_runtime(
        audit_subdir="04_kill_switch",
        auto_approve=True,
        kill_switch_path=ks_path,
    )

    ks_agent = make_identity(
        agent_id="ops-agent-v2",
        name="OpsAgent",
        owner="bob@empresa.com",
        scopes=[AgentScope.READ_FILES],
        environment=AgentEnvironment.DEV,
    )

    print("\n  Passo 1: execução normal ANTES do kill switch")
    result = runtime_ks.execute(ks_agent, "read_files", {"path": "/health"})
    print_result("read_files (antes do kill switch)", result)

    print("\n  Passo 2: ativando o kill switch de emergência...")
    approval_ks.activate_kill_switch("incidente de segurança detectado — P0")
    print(f"  Kill switch ativo: {approval_ks.is_kill_switch_active()}")

    print("\n  Passo 3: tentativa de execução com kill switch ATIVO")
    result = runtime_ks.execute(ks_agent, "read_files", {"path": "/health"})
    print_result("read_files (com kill switch ativo)", result)

    print("\n  Passo 4: tentativa de ação destrutiva com kill switch ATIVO")
    result = runtime_ks.execute(ks_agent, "delete_files", {"path": "/data"})
    print_result("delete_files (com kill switch ativo)", result)

    print("\n  Passo 5: desativando o kill switch")
    approval_ks.deactivate_kill_switch()
    print(f"  Kill switch ativo: {approval_ks.is_kill_switch_active()}")

    print("\n  Passo 6: execução normal APÓS desativação do kill switch")
    result = runtime_ks.execute(ks_agent, "read_files", {"path": "/health"})
    print_result("read_files (após desativação)", result)

    # ── Trilhas de auditoria ──────────────────────────────────────────────────
    print_header("TRILHA DE AUDITORIA — Kill Switch")
    print_audit_trail(audit_ks)
    print_header("VERIFICAÇÃO DA HASH CHAIN — Kill Switch")
    print_chain_verification(audit_ks)


if __name__ == "__main__":
    run()
