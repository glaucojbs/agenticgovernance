"""
EXEMPLO 08 — Relatório de Compliance e PII Masking
====================================================

Demonstra:
  1. PII masking automático no audit log (e-mails, CPFs, tokens redactados)
  2. Geração de relatório de evidências mapeado a NIST AI RMF / ISO 42001
  3. Aprovação M-de-N para operação crítica
  4. Policy dry-run comparando antes × depois de uma mudança

Execute: python -m examples.08_compliance_report
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from examples._shared.setup import POLICIES_DIR, build_runtime, make_identity, print_header
from governance.approval.multi import NApprovalGate
from governance.compliance.reporter import ComplianceReporter
from governance.identity.models import AgentEnvironment, AgentScope
from governance.masking.masker import PIIMasker
from governance.policy.dryrun import PolicyDryRun
from governance.policy.engine import ActionRequest, RiskLevel
from governance.runtime.config import GovernanceConfig
from governance.signing.signer import AuditSigner, SignedAuditLogger


def run() -> None:
    print_header("EXEMPLO 08 — Compliance, PII Masking e Dry-run")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ── 1. PII Masking ────────────────────────────────────────────────────
        print_header("CAMADA 1 — PII Masking no Audit Log")

        masker = PIIMasker.with_defaults()
        signer = AuditSigner.generate()
        signed_audit = SignedAuditLogger(tmp / "audit.jsonl", signer)

        print("  Masker configurado com padrões: e-mail, CPF, CNPJ, token, IP, cartão")

        # Testa masking antes de conectar ao runtime
        test_data = {
            "query": "SELECT * FROM users WHERE email='maria@empresa.com'",
            "user_cpf": "123.456.789-00",
            "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
            "ip": "192.168.1.100",
        }
        masked = masker.mask_details(test_data)
        print(f"\n  Original : {test_data}")
        print(f"  Mascarado: {masked}")

        cfg = GovernanceConfig(pii_masker=masker)
        runtime, audit_plain, approval, _, _ = build_runtime(audit_subdir="08_compliance")
        # Usa o signed+masked audit
        from governance.approval.gate import ApprovalGate
        from governance.budget.guard import BudgetConfig, BudgetGuard
        from governance.policy.engine import PolicyEngine
        from governance.registry.catalog import AgentRegistry, ToolDefinition, ToolRegistry
        from governance.runtime.governed import GovernedAgentRuntime

        tools = ToolRegistry()
        for name, risk, scope in [
            ("read_files",     RiskLevel.LOW,    AgentScope.READ_FILES),
            ("query_database", RiskLevel.LOW,    AgentScope.READ_DATABASE),
            ("send_email",     RiskLevel.MEDIUM, AgentScope.SEND_EMAIL),
            ("delete_files",   RiskLevel.HIGH,   AgentScope.DELETE_FILES),
        ]:
            tools.register(
                ToolDefinition(name=name, description=name, risk_level=risk, required_scope=scope),
                implementation=lambda n=name, **kw: f"[OK] {n}",
            )

        masked_runtime = GovernedAgentRuntime(
            policy_engine=PolicyEngine(POLICIES_DIR),
            audit_logger=signed_audit,
            budget_guard=BudgetGuard(BudgetConfig(max_calls=50)),
            approval_gate=ApprovalGate(kill_switch_path=tmp / ".ks", auto_approve=True),
            tool_registry=tools,
            agent_registry=AgentRegistry(),
            config=cfg,
        )

        agent = make_identity(
            agent_id="compliance-agent", name="ComplianceAgent",
            owner="alice@empresa.com",
            scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE, AgentScope.SEND_EMAIL],
            environment=AgentEnvironment.DEV,
        )

        print_header("EXECUÇÕES COM PII MASKING ATIVO")
        # Parâmetros que contêm PII — serão mascarados antes de gravar no log
        masked_runtime.execute(agent, "query_database", {
            "query": "SELECT * FROM clientes WHERE cpf='123.456.789-00'"
        })
        masked_runtime.execute(agent, "send_email", {
            "to": "cliente@exemplo.com", "subject": "Relatório mensal"
        })
        masked_runtime.execute(agent, "read_files", {"path": "/dados/relatorio.csv"})
        masked_runtime.execute(agent, "delete_files", {"path": "/tmp/cache"})

        # Mostra que o log mascarou os dados
        events = signed_audit.replay()
        print("  Últimos 3 eventos no audit (com PII mascarado):")
        for evt in events[-3:]:
            if evt.details:
                print(f"    #{evt.sequence} {evt.event_type.value}: {evt.details}")

        # ── 2. Aprovação M-de-N ────────────────────────────────────────────────
        print_header("CAMADA 2 — Aprovação M-de-N para Operação Crítica")

        gate_approve = NApprovalGate(
            required_approvals=2,
            available_approvers=["senior-eng-1", "senior-eng-2", "security-eng"],
            timeout_seconds=300,
            auto_approve_count=2,
        )
        req = gate_approve.request_approval(
            agent_id=agent.id, agent_name=agent.name,
            tool_name="wipe_database",
            parameters={"confirm": "yes", "database": "producao"},
            risk_level="critical",
            reason="migração de dados urgente",
        )
        status = "✓ CONCEDIDA" if req.is_granted else "✗ NEGADA"
        print(f"  Aprovação: {status}")
        print(f"  Votos    : {req.vote_summary()}")
        for vote in req.votes:
            icon = "✓" if vote.decision == "approve" else "✗"
            print(f"    {icon} {vote.approver_name}: {vote.notes}")

        gate_deny = NApprovalGate(
            required_approvals=2,
            available_approvers=["senior-eng-1", "senior-eng-2"],
            timeout_seconds=300,
            auto_deny_count=1,
        )
        req2 = gate_deny.request_approval(
            agent_id=agent.id, agent_name=agent.name,
            tool_name="wipe_database", parameters={},
            risk_level="critical", reason="teste de negação",
        )
        print(f"\n  Com 1 negação: {'✓ OK' if req2.is_granted else '✗ NEGADA (1 deny impossibilita 2 approves)'}")

        # ── 3. Policy Dry-run ─────────────────────────────────────────────────
        print_header("CAMADA 3 — Policy Dry-run (mudança de política)")

        # Cria um diretório de políticas "proposto" mais restritivo
        proposed_dir = tmp / "policies_proposed"
        proposed_dir.mkdir()
        # Copia as políticas atuais e adiciona uma restrição
        import shutil
        for f in Path(POLICIES_DIR).glob("*.yaml"):
            shutil.copy(f, proposed_dir / f.name)
        # Adiciona regra extra que nega query_database em prod
        extra_policy = proposed_dir / "extra-restrictions.yaml"
        extra_policy.write_text("""rules:
  - name: deny-db-prod-new
    decision: DENY
    tools:
      - query_database
    environments: ["prod"]
    reason: "Nova restrição proposta: query_database bloqueado em prod (SOC2)"
""")

        dry_run = PolicyDryRun.from_dirs(POLICIES_DIR, proposed_dir)
        test_requests = [
            ActionRequest(
                agent_id="test", agent_name="Test",
                tool_name=tool, parameters={},
                environment=env,
                scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE, AgentScope.SEND_EMAIL],
                risk_level=RiskLevel.LOW,
            )
            for tool in ["read_files", "query_database", "delete_files", "send_email"]
            for env in ["dev", "prod"]
        ]
        report = dry_run.compare(test_requests)
        print(report.render())

        # ── 4. Compliance Report ───────────────────────────────────────────────
        print_header("CAMADA 4 — Relatório de Evidências de Compliance")

        reporter = ComplianceReporter(signed_audit._log_path)
        evidence = reporter.generate()
        print(evidence.render())

        out_json = tmp / "compliance_evidence.json"
        out_json.write_text(evidence.to_json())
        print(f"\n  Evidências salvas em: {out_json}")
        print("  (em produção: assinar com chave do CISO e arquivar em WORM storage)")

        # ── 5. Verificação final ──────────────────────────────────────────────
        print_header("VERIFICAÇÃO FINAL — Assinaturas + Chain")
        sig_result = signed_audit.verify_signatures(signer.public_key_pem())
        chain_result = signed_audit.verify_chain()
        print(f"  Assinaturas Ed25519 : {'✓ todas válidas' if sig_result['valid'] else '✗ inválidas'} ({sig_result['total']} entradas)")
        print(f"  Hash chain          : {'✓ válida' if chain_result.valid else '✗ inválida'} ({chain_result.total_entries} entradas)")


if __name__ == "__main__":
    run()
