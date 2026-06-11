"""
CLI de operações de governança agêntica.

Comandos disponíveis:
  governance kill-switch status          — verifica se o kill switch está ativo
  governance kill-switch enable REASON   — ativa o kill switch
  governance kill-switch disable         — desativa o kill switch

  governance audit verify LOG_PATH       — verifica a hash chain do log
  governance audit stats LOG_PATH        — estatísticas do log de auditoria
  governance audit replay LOG_PATH       — imprime todos os eventos

  governance policy eval                 — simula uma avaliação de política
  governance policy dryrun               — compara dois diretórios de política

  governance forensics LOG_PATH          — reconstrói timeline de incidente

  governance report compliance LOG_PATH  — gera relatório de evidências

Execute: python -m governance.cli --help
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_kill_switch(args: argparse.Namespace) -> int:
    from governance.approval.gate import ApprovalGate

    ks_path = Path(args.kill_switch_file)
    gate = ApprovalGate(kill_switch_path=ks_path)

    if args.ks_action == "status":
        active = gate.is_kill_switch_active()
        if active:
            content = ks_path.read_text().strip()
            print("  🚨 KILL SWITCH ATIVO")
            print(f"     {content}")
        else:
            print("  ✓  Kill switch INATIVO — agentes operando normalmente")
        return 0

    if args.ks_action == "enable":
        reason = getattr(args, "reason", "ativado pelo operador via CLI")
        gate.activate_kill_switch(reason)
        print(f"  🚨 Kill switch ATIVADO: {reason}")
        return 0

    if args.ks_action == "disable":
        gate.deactivate_kill_switch()
        print("  ✓  Kill switch DESATIVADO — agentes podem voltar a operar")
        return 0

    return 1


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from governance.audit.logger import AuditLogger

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"  ✗  Arquivo não encontrado: {log_path}", file=sys.stderr)
        return 1

    logger = AuditLogger(log_path)
    result = logger.verify_chain()

    if result.valid:
        print("  ✓  Hash chain VÁLIDA")
        print(f"     Entradas verificadas: {result.total_entries}")
    else:
        print(f"  ✗  ADULTERAÇÃO DETECTADA na entrada #{result.first_broken_at}")
        print(f"     {result.error}", file=sys.stderr)
        return 1
    return 0


def cmd_audit_stats(args: argparse.Namespace) -> int:
    from governance.audit.logger import AuditLogger

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"  ✗  Arquivo não encontrado: {log_path}", file=sys.stderr)
        return 1

    logger = AuditLogger(log_path)
    events = logger.replay()

    if not events:
        print("  (log vazio)")
        return 0

    from collections import Counter

    type_counts = Counter(e.event_type.value for e in events)
    agent_counts = Counter(e.agent_id for e in events if e.agent_id)

    print(f"  Arquivo   : {log_path}")
    print(f"  Entradas  : {len(events)}")
    print(f"  Período   : {events[0].timestamp[11:19]} → {events[-1].timestamp[11:19]}")
    print("\n  Por tipo de evento:")
    for event_type, count in type_counts.most_common():
        print(f"    {event_type:<30} {count:>6}")
    print("\n  Por agente:")
    for agent_id, count in agent_counts.most_common(10):
        print(f"    {agent_id:<36} {count:>6}")
    return 0


def cmd_audit_replay(args: argparse.Namespace) -> int:
    from governance.audit.logger import AuditLogger

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"  ✗  Arquivo não encontrado: {log_path}", file=sys.stderr)
        return 1

    logger = AuditLogger(log_path)
    events = logger.replay()

    agent_filter = getattr(args, "agent", None)
    for event in events:
        if agent_filter and event.agent_id != agent_filter:
            continue
        ts = event.timestamp[11:19]
        agent = (event.agent_name or event.agent_id or "-")[:20]
        tool = (event.tool_name or "-")[:20]
        et = event.event_type.value[:25]
        print(f"  #{event.sequence:04d} [{ts}] {et:<25} agent={agent:<20} tool={tool}")

    return 0


def cmd_policy_eval(args: argparse.Namespace) -> int:
    from governance.identity.models import AgentEnvironment, AgentScope
    from governance.policy.engine import ActionRequest, PolicyEngine, RiskLevel

    policies_dir = Path(args.policies_dir)
    engine = PolicyEngine(policies_dir)

    try:
        env = AgentEnvironment(args.environment)
    except ValueError:
        print(f"  ✗  Ambiente inválido: {args.environment}", file=sys.stderr)
        return 1

    try:
        risk = RiskLevel(args.risk_level)
    except ValueError:
        print(f"  ✗  Nível de risco inválido: {args.risk_level}", file=sys.stderr)
        return 1

    scopes = []
    for s in (args.scopes or "").split(","):
        s = s.strip()
        if s:
            try:
                scopes.append(AgentScope(s))
            except ValueError:
                print(f"  ⚠  Escopo desconhecido ignorado: {s}")

    request = ActionRequest(
        agent_id=args.agent_id or "cli-test",
        agent_name=args.agent_name or "CLI Test Agent",
        tool_name=args.tool_name,
        parameters={},
        environment=env,
        scopes=scopes,
        risk_level=risk,
    )
    result = engine.evaluate(request)

    icon = {"ALLOW": "✓", "DENY": "✗", "REQUIRE_APPROVAL": "⏳"}[result.decision.value]
    print(f"\n  {icon}  DECISÃO: {result.decision.value}")
    print(f"     Motivo  : {result.reason}")
    if result.matched_rule:
        print(f"     Regra   : {result.matched_rule} ({result.policy_file})")
    return 0 if result.decision.value == "ALLOW" else 1


def cmd_policy_dryrun(args: argparse.Namespace) -> int:
    from governance.identity.models import AgentEnvironment, AgentScope
    from governance.policy.dryrun import PolicyDryRun
    from governance.policy.engine import ActionRequest, RiskLevel

    dry_run = PolicyDryRun.from_dirs(
        current_dir=args.current_dir,
        proposed_dir=args.proposed_dir,
    )

    # Carrega requests de teste de um JSON ou usa defaults
    if args.requests_file:
        raw = json.loads(Path(args.requests_file).read_text())
        requests = [ActionRequest(**r) for r in raw]
    else:
        # Requests de exemplo para demonstração
        requests = [
            ActionRequest(
                agent_id="test",
                agent_name="Test",
                tool_name=tool,
                parameters={},
                environment=AgentEnvironment.DEV,
                scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
                risk_level=RiskLevel.LOW,
            )
            for tool in [
                "read_files",
                "delete_files",
                "query_database",
                "send_email",
                "unknown_tool",
            ]
        ]

    report = dry_run.compare(requests)
    print(report.render())
    return 1 if report.restrictions else 0


def cmd_forensics(args: argparse.Namespace) -> int:
    from governance.forensics.replayer import IncidentReplayer

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"  ✗  Arquivo não encontrado: {log_path}", file=sys.stderr)
        return 1

    replayer = IncidentReplayer(log_path)

    ok, msg = replayer.verify_integrity()
    print(f"  {'✓' if ok else '✗'}  Integridade: {msg}")

    agent_ids = getattr(args, "agents", None)
    agents = [a.strip() for a in agent_ids.split(",")] if agent_ids else None
    timeline = replayer.replay(agent_ids=agents)
    print(timeline.render_timeline())
    return 0


def cmd_report_compliance(args: argparse.Namespace) -> int:
    from governance.compliance.reporter import ComplianceReporter

    log_path = Path(args.log_path)
    if not log_path.exists():
        print(f"  ✗  Arquivo não encontrado: {log_path}", file=sys.stderr)
        return 1

    reporter = ComplianceReporter(log_path)
    evidence = reporter.generate()
    print(evidence.render())

    if args.output:
        out = Path(args.output)
        out.write_text(evidence.to_json())
        print(f"\n  Relatório JSON salvo em: {out}")

    return 0


def cmd_guardrail_scan(args: argparse.Namespace) -> int:
    from governance.guardrails.scanner import GuardrailScanner, ScanDirection

    scanner = GuardrailScanner.with_defaults()
    direction = ScanDirection(args.direction)
    result = scanner.scan_text(args.text, direction, tool_name=getattr(args, "tool", None))

    icon = {"ALLOW": "✓", "FLAG": "⚠", "BLOCK": "✗"}[result.verdict.value]
    print(f"\n  {icon}  VEREDITO: {result.verdict.value}  ({direction.value})")
    if not result.findings:
        print("     (nenhum achado)")
    for finding in result.findings:
        print(f"     - [{finding.detector}] {finding.rule}: {finding.message}")
    return 0 if result.verdict.value != "BLOCK" else 1


def cmd_aibom(args: argparse.Namespace) -> int:
    from governance.identity.models import AgentScope
    from governance.policy.engine import RiskLevel
    from governance.registry.catalog import ToolDefinition, ToolRegistry
    from governance.signing.signer import AuditSigner
    from governance.supply_chain.aibom import generate_aibom
    from governance.supply_chain.tool_integrity import ToolIntegrityRegistry

    registry = ToolRegistry()
    demo = [
        ("read_files", "Lê arquivos", RiskLevel.LOW, AgentScope.READ_FILES),
        ("query_database", "Consulta o banco", RiskLevel.LOW, AgentScope.READ_DATABASE),
        ("send_email", "Envia e-mail", RiskLevel.MEDIUM, AgentScope.SEND_EMAIL),
        ("delete_files", "Apaga arquivos", RiskLevel.HIGH, AgentScope.DELETE_FILES),
    ]
    for name, desc, risk, scope in demo:
        registry.register(
            ToolDefinition(name=name, description=desc, risk_level=risk, required_scope=scope),
            implementation=lambda **kw: None,
        )

    integrity = ToolIntegrityRegistry(signer=AuditSigner.generate())
    integrity.pin_registry(registry, server_id="internal-mcp")
    bom = generate_aibom(registry, integrity)
    print(bom.render())

    if args.output:
        Path(args.output).write_text(bom.to_json())
        print(f"\n  AI-BOM salvo em: {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="governance",
        description="CLI de operações de governança agêntica",
    )
    parser.add_argument(
        "--kill-switch-file",
        default=".kill_switch",
        help="Caminho do arquivo de kill switch (padrão: .kill_switch)",
    )

    sub = parser.add_subparsers(dest="command")

    # ── kill-switch ───────────────────────────────────────────────────────────
    ks = sub.add_parser("kill-switch", help="Gerencia o kill switch global")
    ks_sub = ks.add_subparsers(dest="ks_action")
    ks_sub.add_parser("status", help="Verifica se o kill switch está ativo")
    ks_enable = ks_sub.add_parser("enable", help="Ativa o kill switch")
    ks_enable.add_argument("reason", help="Motivo da ativação")
    ks_sub.add_parser("disable", help="Desativa o kill switch")

    # ── audit ─────────────────────────────────────────────────────────────────
    audit = sub.add_parser("audit", help="Operações no audit log")
    audit_sub = audit.add_subparsers(dest="audit_action")

    av = audit_sub.add_parser("verify", help="Verifica a hash chain")
    av.add_argument("log_path", help="Caminho do arquivo JSONL")

    ast = audit_sub.add_parser("stats", help="Estatísticas do log")
    ast.add_argument("log_path", help="Caminho do arquivo JSONL")

    ar = audit_sub.add_parser("replay", help="Imprime todos os eventos")
    ar.add_argument("log_path", help="Caminho do arquivo JSONL")
    ar.add_argument("--agent", help="Filtrar por agent_id")

    # ── policy ────────────────────────────────────────────────────────────────
    pol = sub.add_parser("policy", help="Operações de política")
    pol_sub = pol.add_subparsers(dest="policy_action")

    pe = pol_sub.add_parser("eval", help="Simula uma avaliação de política")
    pe.add_argument("--policies-dir", default="policies", help="Diretório de políticas YAML")
    pe.add_argument("--tool-name", required=True)
    pe.add_argument("--agent-id", default="test-agent")
    pe.add_argument("--agent-name", default="Test Agent")
    pe.add_argument("--environment", default="dev", choices=["dev", "staging", "prod"])
    pe.add_argument("--risk-level", default="low", choices=["low", "medium", "high", "critical"])
    pe.add_argument("--scopes", default="", help="Escopos separados por vírgula")

    pd = pol_sub.add_parser("dryrun", help="Compara dois conjuntos de políticas")
    pd.add_argument("current_dir", help="Diretório com as políticas atuais")
    pd.add_argument("proposed_dir", help="Diretório com as políticas propostas")
    pd.add_argument("--requests-file", help="JSON com ActionRequests de teste")

    # ── forensics ────────────────────────────────────────────────────────────
    foren = sub.add_parser("forensics", help="Reconstrói timeline de incidente")
    foren.add_argument("log_path", help="Caminho do arquivo JSONL")
    foren.add_argument("--agents", help="agent_ids separados por vírgula")

    # ── report ───────────────────────────────────────────────────────────────
    report = sub.add_parser("report", help="Gera relatórios")
    report_sub = report.add_subparsers(dest="report_type")
    rc = report_sub.add_parser("compliance", help="Relatório de evidências de compliance")
    rc.add_argument("log_path", help="Caminho do arquivo JSONL")
    rc.add_argument("--output", help="Salva relatório JSON neste arquivo")

    # ── guardrail ───────────────────────────────────────────────────────────
    gr = sub.add_parser("guardrail", help="Inspeção de conteúdo (guardrails)")
    gr_sub = gr.add_subparsers(dest="guardrail_action")
    grs = gr_sub.add_parser("scan", help="Varre um texto em busca de injeção/exfiltração")
    grs.add_argument("text", help="Texto a inspecionar")
    grs.add_argument("--direction", default="input", choices=["input", "output"])
    grs.add_argument("--tool", help="Nome da ferramenta (ativa DLP de egress)")

    # ── aibom ───────────────────────────────────────────────────────────────
    ab = sub.add_parser("aibom", help="Gera um AI Bill of Materials de demonstração")
    ab.add_argument("--output", help="Salva o AI-BOM JSON neste arquivo")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "kill-switch":
        return cmd_kill_switch(args)

    if args.command == "audit":
        if args.audit_action == "verify":
            return cmd_audit_verify(args)
        if args.audit_action == "stats":
            return cmd_audit_stats(args)
        if args.audit_action == "replay":
            return cmd_audit_replay(args)

    if args.command == "policy":
        if args.policy_action == "eval":
            return cmd_policy_eval(args)
        if args.policy_action == "dryrun":
            return cmd_policy_dryrun(args)

    if args.command == "forensics":
        return cmd_forensics(args)

    if args.command == "report" and getattr(args, "report_type", None) == "compliance":
        return cmd_report_compliance(args)

    if args.command == "guardrail" and getattr(args, "guardrail_action", None) == "scan":
        return cmd_guardrail_scan(args)

    if args.command == "aibom":
        return cmd_aibom(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
