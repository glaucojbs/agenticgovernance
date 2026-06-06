"""Testes do reporter de compliance (incl. OWASP Agentic Top 10) e model card."""

import tempfile
from pathlib import Path

from governance.audit.logger import AuditEventType, AuditLogger
from governance.compliance.model_card import (
    NIST_GENAI_RISK_CATEGORIES,
    generate_model_card,
)
from governance.compliance.reporter import ComplianceReporter


def _log_with_agentic_events(path):
    audit = AuditLogger(path)
    audit.log(AuditEventType.POLICY_DECISION, agent_id="a", details={"decision": "ALLOW"})
    audit.log(AuditEventType.GUARDRAIL_BLOCKED, agent_id="a", details={"direction": "input"})
    audit.log(AuditEventType.TOOL_INTEGRITY_VIOLATION, agent_id="a", tool_name="send_email")
    audit.log(AuditEventType.MEMORY_QUARANTINED, agent_id="a")
    audit.log(AuditEventType.A2A_MESSAGE_REJECTED, agent_id="a")
    return audit


class TestComplianceReporter:
    def test_agentic_controls_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            _log_with_agentic_events(path)
            evidence = ComplianceReporter(path).generate()
            frameworks = {c.framework for c in evidence.controls}
            assert "OWASP Agentic" in frameworks
            control_ids = {c.control_id for c in evidence.controls}
            assert "ASI01" in control_ids  # Goal Hijacking (guardrail)
            assert "ASI06" in control_ids or "ASI07" in control_ids  # supply chain
            assert "ASI09" in control_ids  # memory poisoning
            assert "ASI04" in control_ids  # inter-agent comm

    def test_chain_valid_in_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            _log_with_agentic_events(path)
            evidence = ComplianceReporter(path).generate()
            assert evidence.chain_valid
            assert evidence.total_events == 5

    def test_json_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.jsonl"
            _log_with_agentic_events(path)
            evidence = ComplianceReporter(path).generate()
            assert "OWASP Agentic" in evidence.to_json()


class TestModelCard:
    def test_generate_defaults(self):
        card = generate_model_card(
            "DataAnalyst", "1.0", "alice@x.com", "análise de dados de vendas"
        )
        assert card.name == "DataAnalyst"
        assert card.governance_controls  # preenchido com defaults
        assert card.risk_categories_addressed

    def test_render_and_json(self):
        card = generate_model_card(
            "Agent", "2.0", "owner@x.com", "uso x", granted_scopes=["read:files"]
        )
        assert "# Model Card" in card.render()
        assert "read:files" in card.render()
        assert '"version": "2.0"' in card.to_json()

    def test_nist_genai_has_twelve_categories(self):
        assert len(NIST_GENAI_RISK_CATEGORIES) == 12
