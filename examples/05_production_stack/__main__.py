"""
EXEMPLO 05 — Stack de Produção Completo
========================================

Demonstra a camada "big tech" sobre o runtime básico:
  1. OpenTelemetry — trace de cada ação (console exporter por padrão)
  2. Assinatura Ed25519 — cada entrada de auditoria é assinada
  3. Detector de anomalias — alertas em tempo real
  4. OPA client — motor de política com fallback automático para YAML
  5. Verificação de assinaturas ao final

Para usar com a stack Docker (Jaeger + Grafana + OPA):
    docker compose up -d
    OTEL_EXPORTER=otlp OTEL_ENDPOINT=http://localhost:4318 python -m examples.05_production_stack

Execute local (sem Docker):
    python -m examples.05_production_stack
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from examples._shared.setup import POLICIES_DIR, make_identity, print_header
from governance.anomaly.detector import AlertSeverity, AnomalyDetector
from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.engine import PolicyEngine
from governance.policy.opa_client import OpaPolicyEngine
from governance.signing.signer import AuditSigner, SignedAuditLogger
from governance.telemetry.otel import GovernanceTelemetry


def run() -> None:
    print_header("EXEMPLO 05 — Stack de Produção Completo")
    print("""
  Este exemplo demonstra as camadas adicionais de segurança e observabilidade
  que separam um sistema de produção de um PoC:
    • OpenTelemetry (traces + métricas)
    • Assinatura criptográfica Ed25519 no audit log
    • Detector de anomalias em tempo real
    • OPA como policy engine (com fallback YAML)
""")

    # ── 1. OpenTelemetry — configura providers globais ─────────────────────
    print_header("TELEMETRIA — OpenTelemetry")
    # export_to_console=False para não poluir a saída do exemplo
    # Em produção: OTEL_EXPORTER=otlp OTEL_ENDPOINT=http://jaeger:4318
    telemetry = GovernanceTelemetry.noop()
    print("  ✓ TracerProvider e MeterProvider configurados")
    print("  → Em produção: OTEL_EXPORTER=otlp OTEL_ENDPOINT=http://jaeger:4318")
    print("  → Traces visíveis em: http://localhost:16686 (Jaeger)")
    print("  → Métricas em: http://localhost:3000 (Grafana)")

    # ── 2. Assinatura Ed25519 ─────────────────────────────────────────────
    print_header("ASSINATURA CRIPTOGRÁFICA — Ed25519")
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        signer = AuditSigner.generate()
        public_pem = signer.public_key_pem()
        print("  ✓ Par de chaves Ed25519 gerado")
        print("  → Chave pública (distribuir a auditores):\n")
        for line in public_pem.strip().splitlines():
            print(f"    {line}")

        signed_audit = SignedAuditLogger(tmp / "signed_audit.jsonl", signer)
        print(f"\n  ✓ SignedAuditLogger configurado em {signed_audit._log_path}")

        # ── 3. Detector de anomalias ──────────────────────────────────────
        print_header("ANOMALY DETECTOR")
        alerts_capturados = []

        def alert_capture(alert):
            alerts_capturados.append(alert)
            icon = {"info": "ℹ️ ", "warning": "⚠️ ", "critical": "🚨"}[alert.severity]
            print(
                f"  {icon} [{alert.severity.upper()}] {alert.rule_name}\n     {alert.description}"
            )

        detector = AnomalyDetector(
            max_calls_per_minute=5.0,  # baixo para demonstrar o alerta
            max_deny_rate=0.4,
            max_consecutive_denies=3,
            alert_handlers=[alert_capture],
        )
        print("  ✓ Detector configurado (threshold: 5 calls/min, deny_rate: 40%)")

        # ── 4. OPA client (com fallback) ──────────────────────────────────
        print_header("MOTOR DE POLÍTICA — OPA + fallback YAML")
        opa_engine = OpaPolicyEngine(
            opa_url="http://localhost:8181",
            fallback=PolicyEngine(POLICIES_DIR),
            timeout_seconds=0.5,
        )
        opa_available = opa_engine._check_opa()
        if opa_available:
            print("  ✓ OPA disponível em http://localhost:8181 — usando Rego")
        else:
            print("  ℹ️  OPA offline — fallback YAML ativo")
            print("      (execute 'docker compose up' para ativar o OPA)")

        # ── 5. Runtime com todos os subsistemas ───────────────────────────
        print_header("RUNTIME COMPLETO")
        from governance.approval.gate import ApprovalGate
        from governance.budget.guard import BudgetConfig, BudgetGuard
        from governance.policy.engine import RiskLevel
        from governance.registry.catalog import AgentRegistry, ToolDefinition, ToolRegistry
        from governance.runtime.governed import GovernedAgentRuntime

        tools = ToolRegistry()
        _tool_defs = [
            ("read_files", RiskLevel.LOW, AgentScope.READ_FILES),
            ("delete_files", RiskLevel.HIGH, AgentScope.DELETE_FILES),
            ("query_database", RiskLevel.LOW, AgentScope.READ_DATABASE),
            ("send_email", RiskLevel.MEDIUM, AgentScope.SEND_EMAIL),
        ]
        for _name, _risk, _scope in _tool_defs:

            def _make_impl(n: str):
                return lambda **kw: f"[SIMULADO] {n} executado"

            tools.register(
                ToolDefinition(
                    name=_name,
                    description=_name,
                    risk_level=_risk,
                    required_scope=_scope,
                ),
                implementation=_make_impl(_name),
            )

        ks_path = tmp / ".kill_switch"
        approval = ApprovalGate(kill_switch_path=ks_path, auto_deny=True)
        budget = BudgetGuard(BudgetConfig(max_calls=50, max_cost_usd=10.0))
        agents = AgentRegistry()

        runtime = GovernedAgentRuntime(
            policy_engine=opa_engine,
            audit_logger=signed_audit,
            budget_guard=budget,
            approval_gate=approval,
            tool_registry=tools,
            agent_registry=agents,
            telemetry=telemetry,
            anomaly_detector=detector,
        )
        print("  ✓ GovernedAgentRuntime com OTEL + AnomalyDetector + SignedAuditLogger")

        # ── 6. Execuções demonstrando as camadas ──────────────────────────
        print_header("EXECUÇÕES COM TODAS AS CAMADAS ATIVAS")
        agent = make_identity(
            agent_id="prod-agent-v1",
            name="ProductionAgent",
            owner="devops@empresa.com",
            scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
            environment=AgentEnvironment.DEV,
        )

        print(f"\n  Agente : {agent.name} | Escopos: {[s.value for s in agent.scopes]}")

        # Ação legítima
        r = runtime.execute(agent, "read_files", {"path": "/data/config.json"})
        _print_exec("read_files (legítimo)", r)

        # Ação negada — gera dado para anomaly detector
        for i in range(4):
            r = runtime.execute(agent, "delete_files", {"path": f"/data/{i}"})
        _print_exec("delete_files ×4 (ativa anomalia de negações consecutivas)", r)

        # Ação de alto risco — REQUIRE_APPROVAL → negada (auto_deny=True)
        r = runtime.execute(agent, "read_files", risk_level=RiskLevel.HIGH)
        _print_exec("read_files HIGH risk (aprovação negada)", r)

        # ── 7. Verificação de assinaturas ─────────────────────────────────
        print_header("VERIFICAÇÃO DE ASSINATURAS Ed25519")
        sig_result = signed_audit.verify_signatures(public_pem)
        chain_result = signed_audit.verify_chain()

        if sig_result["valid"]:
            print(f"  ✓ Todas as {sig_result['total']} assinaturas são válidas")
        else:
            print(
                f"  ✗ {len(sig_result['invalid_entries'])} entradas com assinatura inválida: "
                f"{sig_result['invalid_entries']}"
            )

        if chain_result.valid:
            print(f"  ✓ Hash chain VÁLIDA ({chain_result.total_entries} entradas)")
        else:
            print(f"  ✗ Hash chain INVÁLIDA: {chain_result.error}")

        # ── 8. Resumo de anomalias ────────────────────────────────────────
        print_header("RESUMO DE ANOMALIAS DETECTADAS")
        criticals = detector.get_alerts(severity=AlertSeverity.CRITICAL)
        warnings = detector.get_alerts(severity=AlertSeverity.WARNING)
        infos = detector.get_alerts(severity=AlertSeverity.INFO)
        print(f"\n  🚨 CRITICAL : {len(criticals)}")
        print(f"  ⚠️  WARNING  : {len(warnings)}")
        print(f"  ℹ️  INFO     : {len(infos)}")
        print(f"\n  Stats do agente '{agent.id}':")
        stats = detector.get_agent_stats(agent.id)
        for k, v in stats.items():
            print(f"    {k}: {v}")

        # ── 9. Trace ID de correlação ─────────────────────────────────────
        print_header("TRACE ID — CORRELAÇÃO OTEL")
        print("""
  Cada ExecutionResult agora carrega um trace_id:
    result.trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"

  No Jaeger (http://localhost:16686):
    Search → Service: agentic-governance → Find Traces
    Cada ação é um span com atributos:
      governance.agent.id, governance.tool.name,
      governance.policy.decision, governance.risk.level

  No Grafana (http://localhost:3000):
    Dashboard "Governança Agêntica" → métricas em tempo real
""")

    telemetry.shutdown()


def _print_exec(label: str, result) -> None:
    icon = "✓" if result.success else "✗"
    status = "OK" if result.success else "BLOQUEADO"
    tid = f" | trace={result.trace_id[:8]}..." if result.trace_id else ""
    print(f"  {icon} {label} → {status}{tid}")
    if not result.success:
        print(f"    motivo: {result.error}")


if __name__ == "__main__":
    run()
