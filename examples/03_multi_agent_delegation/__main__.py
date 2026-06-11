"""
EXEMPLO 03 — Delegação multi-agente com cadeia rastreável
==========================================================

Demonstra:
  1. Um humano delega escopos ao agente principal
  2. O agente principal delega um subconjunto ao sub-agente
  3. O sub-agente NÃO herda escopos que não lhe foram delegados
  4. A tentativa de escalada de privilégio é bloqueada
  5. A cadeia de delegação é auditável e rastreável

Hierarquia deste exemplo:
  👤 alice@empresa.com
      └── 🤖 OrchestratorAgent  [read:files, read:database, send:email]
              └── 🤖 DataFetcherAgent  [read:files, read:database]  ← NÃO recebe send:email
                      └── 🤖 ReportAgent [read:files]  ← apenas leitura básica

Execute: python -m examples.03_multi_agent_delegation
"""

from examples._shared.setup import (
    build_runtime,
    make_identity,
    print_audit_trail,
    print_chain_verification,
    print_header,
    print_result,
)
from governance.identity.models import AgentEnvironment, AgentScope, DelegationChain


def run() -> None:
    print_header("EXEMPLO 03 — Delegação Multi-Agente")
    print("""
  Cenário: Um agente orquestrador recebe escopos de um humano e delega
  subconjuntos para sub-agentes especializados. Veremos que sub-agentes
  não podem escalar privilégios além do que receberam.
""")

    runtime, audit, approval, tools, agents = build_runtime(audit_subdir="03_multi_agent")

    # ── Cria as identidades ───────────────────────────────────────────────────
    orchestrator = make_identity(
        agent_id="orchestrator-v1",
        name="OrchestratorAgent",
        owner="alice@empresa.com",
        scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE, AgentScope.SEND_EMAIL],
        environment=AgentEnvironment.DEV,
    )

    data_fetcher = make_identity(
        agent_id="data-fetcher-v1",
        name="DataFetcherAgent",
        owner="alice@empresa.com",
        scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
        environment=AgentEnvironment.DEV,
        parent_id=orchestrator.id,
    )

    report_agent = make_identity(
        agent_id="report-agent-v1",
        name="ReportAgent",
        owner="alice@empresa.com",
        scopes=[AgentScope.READ_FILES],
        environment=AgentEnvironment.DEV,
        parent_id=data_fetcher.id,
    )

    # ── Constrói a cadeia de delegação ────────────────────────────────────────
    chain = DelegationChain()

    print_header("CADEIA DE DELEGAÇÃO")

    # Humano → Orquestrador
    link1 = chain.add_link(
        "alice@empresa.com",
        orchestrator,
        [AgentScope.READ_FILES, AgentScope.READ_DATABASE, AgentScope.SEND_EMAIL],
        reason="Delegação inicial para orquestração de análise de dados",
    )
    print(f"\n  {link1}")

    # Orquestrador → DataFetcher (subconjunto — sem send:email)
    link2 = chain.add_link(
        orchestrator,
        data_fetcher,
        [AgentScope.READ_FILES, AgentScope.READ_DATABASE],
        reason="DataFetcher só precisa ler dados, não enviar e-mails",
    )
    print(f"  {link2}")

    # DataFetcher → ReportAgent (ainda mais restrito)
    link3 = chain.add_link(
        data_fetcher,
        report_agent,
        [AgentScope.READ_FILES],
        reason="ReportAgent só precisa de arquivos estáticos para gerar relatório",
    )
    print(f"  {link3}")

    print(f"\n  Cadeia completa: {chain.render()}")

    # ── Execuções legítimas ───────────────────────────────────────────────────
    print_header("EXECUÇÕES DENTRO DO ESCOPO")

    result = runtime.execute(
        orchestrator,
        "send_email",
        {
            "to": "manager@empresa.com",
            "subject": "Análise completa",
        },
    )
    print_result("OrchestratorAgent → send_email", result)

    result = runtime.execute(
        data_fetcher, "query_database", {"query": "SELECT * FROM dados LIMIT 100"}
    )
    print_result("DataFetcherAgent → query_database", result)

    result = runtime.execute(report_agent, "read_files", {"path": "/reports/template.md"})
    print_result("ReportAgent → read_files", result)

    # ── Tentativas de escalada de privilégio ──────────────────────────────────
    print_header("TENTATIVAS DE ESCALADA DE PRIVILÉGIO")

    print("\n  Teste A: DataFetcher tenta enviar e-mail (não delegado)")
    result = runtime.execute(
        data_fetcher,
        "send_email",
        {
            "to": "hacker@external.com",
            "subject": "Dados confidenciais",
        },
    )
    print_result("DataFetcherAgent → send_email (sem escopo)", result)

    print("\n  Teste B: ReportAgent tenta acessar banco (não delegado)")
    result = runtime.execute(report_agent, "query_database", {"query": "SELECT * FROM usuarios"})
    print_result("ReportAgent → query_database (sem escopo)", result)

    print("\n  Teste C: ReportAgent tenta deletar arquivos")
    result = runtime.execute(report_agent, "delete_files", {"path": "/data"})
    print_result("ReportAgent → delete_files (sem escopo + destrutivo)", result)

    print("\n  Teste D: Tentativa de delegar escopo que o agente não possui")
    try:
        # DataFetcher não tem send:email, portanto não pode delegar
        chain.add_link(
            data_fetcher,
            report_agent,
            [AgentScope.SEND_EMAIL],
            reason="tentativa maliciosa de escalada",
        )
        print("  ✗ FALHA: escalada de privilégio não foi bloqueada!")
    except PermissionError as e:
        print(f"  ✓ BLOQUEADO: {e}")

    # ── Rastreabilidade da cadeia ─────────────────────────────────────────────
    print_header("RASTREABILIDADE DA DELEGAÇÃO")
    print(
        f"\n  Escopos efetivos do OrchestratorAgent : "
        f"{[s.value for s in chain.get_effective_scopes(orchestrator.id)]}"
    )
    print(
        f"  Escopos efetivos do DataFetcherAgent  : "
        f"{[s.value for s in chain.get_effective_scopes(data_fetcher.id)]}"
    )
    print(
        f"  Escopos efetivos do ReportAgent       : "
        f"{[s.value for s in chain.get_effective_scopes(report_agent.id)]}"
    )
    print(f"\n  parent_id do DataFetcher: {data_fetcher.parent_id}")
    print(f"  parent_id do ReportAgent: {report_agent.parent_id}")

    # ── Trilha de auditoria e verificação ─────────────────────────────────────
    print_audit_trail(audit)
    print_header("VERIFICAÇÃO DA HASH CHAIN")
    print_chain_verification(audit)


if __name__ == "__main__":
    run()
