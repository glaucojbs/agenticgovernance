"""
EXEMPLO 02 — Agente com governança completa
============================================

O mesmo agente do exemplo 01 agora é envolvido pelo GovernedAgentRuntime.

O que este exemplo demonstra:
  1. Ação de leitura com escopo correto → PERMITIDA e auditada
  2. Tentativa de ação destrutiva → NEGADA por política (default-deny + regra explícita)
  3. Tentativa sem escopo necessário → NEGADA por política
  4. Verificação da trilha de auditoria com hash chain
  5. O agente simulado nunca consegue executar o que a governança não permite

Execute: python -m examples.02_governed_agent
"""

from examples._shared.setup import (
    build_runtime,
    make_identity,
    print_audit_trail,
    print_chain_verification,
    print_header,
    print_result,
)
from governance.identity.models import AgentEnvironment, AgentScope


def run() -> None:
    print_header("EXEMPLO 02 — Agente com Governança Completa")
    print("""
  Cenário: Um agente de análise de dados recebeu escopos limitados
  (read:files, read:database). Vamos ver o que acontece quando ele
  tenta executar operações dentro e fora do seu escopo.
""")

    # ── Monta o runtime governado ────────────────────────────────────────────
    runtime, audit, approval, tools, agents = build_runtime(
        audit_subdir="02_governed_agent"
    )

    # ── Identidade do agente ─────────────────────────────────────────────────
    agent = make_identity(
        agent_id="data-analyst-v1",
        name="DataAnalystAgent",
        owner="alice@empresa.com",
        scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
        environment=AgentEnvironment.DEV,
    )

    print(f"  Agente  : {agent.name} ({agent.id})")
    print(f"  Dono    : {agent.owner}")
    print(f"  Escopos : {[s.value for s in agent.scopes]}")
    print(f"  Env     : {agent.environment.value}")
    print(f"  Autent. : {'✓' if agent.is_authenticated() else '✗'}")

    # ── Ação 1: Leitura de arquivos — deve PERMITIR ──────────────────────────
    print_header("AÇÃO 1 — Leitura de arquivo (escopo correto)")
    result = runtime.execute(agent, "read_files", {"path": "/data/relatorio.csv"})
    print_result("read_files → /data/relatorio.csv", result)

    # ── Ação 2: Query no banco — deve PERMITIR ───────────────────────────────
    print_header("AÇÃO 2 — Query no banco de dados (escopo correto)")
    result = runtime.execute(
        agent, "query_database", {"query": "SELECT COUNT(*) FROM vendas"}
    )
    print_result("query_database → SELECT COUNT(*) FROM vendas", result)

    # ── Ação 3: Deletar arquivos — deve NEGAR (política explícita) ───────────
    print_header("AÇÃO 3 — Deletar arquivo (ferramenta destrutiva)")
    print("  O agente tenta apagar arquivos. Política: deny-delete-always")
    result = runtime.execute(agent, "delete_files", {"path": "/data/relatorio.csv"})
    print_result("delete_files → /data/relatorio.csv", result)

    # ── Ação 4: Enviar e-mail — deve NEGAR (sem escopo) ──────────────────────
    print_header("AÇÃO 4 — Enviar e-mail (sem escopo send:email)")
    print("  O agente não possui escopo 'send:email' — deve ser negado.")
    result = runtime.execute(
        agent,
        "send_email",
        {"to": "ceo@empresa.com", "subject": "Relatório pronto"},
    )
    print_result("send_email → ceo@empresa.com", result)

    # ── Ação 5: Ferramenta inexistente — deve NEGAR (default-deny) ───────────
    print_header("AÇÃO 5 — Ferramenta desconhecida (default-deny)")
    print("  Ferramenta não cadastrada → default-deny sem exceção.")
    result = runtime.execute(agent, "run_arbitrary_code", {"cmd": "rm -rf /"})
    print_result("run_arbitrary_code", result)

    # ── Trilha de auditoria ──────────────────────────────────────────────────
    print_audit_trail(audit)

    # ── Verificação de integridade da chain ───────────────────────────────────
    print_header("VERIFICAÇÃO DA HASH CHAIN")
    print("  Reconstruindo e verificando o hash de cada entrada...")
    print_chain_verification(audit)

    print("  Arquivo de log:", audit._log_path)
    print()


if __name__ == "__main__":
    run()
