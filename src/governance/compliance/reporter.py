"""
ComplianceReporter — coleta automática de evidências de compliance.

Gera um relatório mapeando os eventos do audit log para controles
específicos do NIST AI RMF, ISO/IEC 42001 e EU AI Act.

Em uma auditoria real, este relatório acompanha as evidências técnicas
(arquivos de log assinados) e demonstra ao auditor que os controles
estão operando conforme documentado.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from governance.audit.logger import AuditEventType, AuditLogger


@dataclass
class ControlEvidence:
    """Evidência de que um controle específico está operando."""

    control_id: str
    control_name: str
    framework: str
    status: str  # "IMPLEMENTED" | "PARTIAL" | "NOT_IMPLEMENTED"
    evidence_count: int
    description: str
    sample_events: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ComplianceEvidence:
    """Relatório completo de evidências de compliance."""

    generated_at: str
    audit_period_start: str | None
    audit_period_end: str | None
    total_events: int
    chain_valid: bool
    controls: list[ControlEvidence] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def render(self) -> str:
        implemented = sum(1 for c in self.controls if c.status == "IMPLEMENTED")
        partial = sum(1 for c in self.controls if c.status == "PARTIAL")
        not_impl = sum(1 for c in self.controls if c.status == "NOT_IMPLEMENTED")

        lines = [
            "╔" + "═" * 72 + "╗",
            "║  COMPLIANCE EVIDENCE REPORT" + " " * 44 + "║",
            "╠" + "═" * 72 + "╣",
            f"║  Gerado em    : {self.generated_at[:19]:<55}║",
            f"║  Período      : {(self.audit_period_start or '?')[:10]} → {(self.audit_period_end or '?')[:10]:<46}║",
            f"║  Total eventos: {self.total_events:<55}║",
            f"║  Hash chain   : {'✓ VÁLIDA' if self.chain_valid else '✗ INVÁLIDA':<55}║",
            "╠" + "═" * 72 + "╣",
            f"║  Controles IMPLEMENTADOS : {implemented:<45}║",
            f"║  Controles PARCIAIS      : {partial:<45}║",
            f"║  Controles NÃO IMPL.     : {not_impl:<45}║",
            "╠" + "═" * 72 + "╣",
        ]

        for ctrl in self.controls:
            icon = {"IMPLEMENTED": "✓", "PARTIAL": "~", "NOT_IMPLEMENTED": "✗"}[ctrl.status]
            name = ctrl.control_name[:35]
            fw = ctrl.framework[:12]
            lines.append(
                f"║  {icon} [{fw:<12}] {ctrl.control_id:<10} {name:<35} ({ctrl.evidence_count:>4} eventos)║"
            )

        lines.append("╚" + "═" * 72 + "╝")
        return "\n".join(lines)

    def to_json(self) -> str:
        return json.dumps(
            {
                "generated_at": self.generated_at,
                "audit_period": {
                    "start": self.audit_period_start,
                    "end": self.audit_period_end,
                },
                "total_events": self.total_events,
                "chain_valid": self.chain_valid,
                "summary": self.summary,
                "controls": [
                    {
                        "control_id": c.control_id,
                        "framework": c.framework,
                        "control_name": c.control_name,
                        "status": c.status,
                        "evidence_count": c.evidence_count,
                        "description": c.description,
                    }
                    for c in self.controls
                ],
            },
            indent=2,
            ensure_ascii=False,
        )


# Mapeamento: (tipo de evento) → controles que ele evidencia
_EVENT_CONTROLS: dict[AuditEventType, list[tuple[str, str, str]]] = {
    # (framework, control_id, control_name)
    AuditEventType.POLICY_DECISION: [
        ("NIST AI RMF", "GOVERN-1.1", "AI Risk Policy"),
        ("ISO/IEC 42001", "6.1", "Risk Assessment"),
        ("EU AI Act", "Art.9", "Risk Management System"),
    ],
    AuditEventType.ACTION_DENIED: [
        ("NIST AI RMF", "MANAGE-1.3", "Risk Response"),
        ("OWASP LLM", "LLM08", "Excessive Agency"),
        ("OWASP Agentic", "ASI02", "Identity & Privilege Abuse"),
    ],
    AuditEventType.ACTION_EXECUTED: [
        ("NIST AI RMF", "MEASURE-2.5", "AI System Monitoring"),
        ("ISO/IEC 42001", "8.4", "AI System Logging"),
        ("EU AI Act", "Art.12", "Record-keeping"),
        ("EU AI Act GPAI", "Art.53", "Technical Documentation"),
    ],
    AuditEventType.APPROVAL_REQUESTED: [
        ("NIST AI RMF", "GOVERN-5.2", "Human Oversight"),
        ("EU AI Act", "Art.14", "Human Oversight"),
    ],
    AuditEventType.APPROVAL_GRANTED: [
        ("NIST AI RMF", "GOVERN-5.2", "Human Oversight"),
        ("EU AI Act", "Art.14", "Human Oversight"),
    ],
    AuditEventType.APPROVAL_DENIED: [
        ("NIST AI RMF", "GOVERN-5.2", "Human Oversight"),
    ],
    AuditEventType.BUDGET_EXCEEDED: [
        ("NIST AI RMF", "MANAGE-2.4", "Resource Management"),
        ("OWASP LLM", "LLM04", "Model DoS"),
    ],
    AuditEventType.KILL_SWITCH_TRIGGERED: [
        ("NIST AI RMF", "MANAGE-3.2", "Incident Response"),
        ("EU AI Act", "Art.14", "Human Oversight"),
    ],
    AuditEventType.KILL_SWITCH_ACTIVATED: [
        ("NIST AI RMF", "MANAGE-3.2", "Incident Response"),
    ],
    AuditEventType.CREDENTIAL_REVOKED: [
        ("NIST AI RMF", "MANAGE-3.1", "Risk Mitigation"),
        ("ISO/IEC 42001", "9.1", "Monitoring"),
    ],
    # ── Fase 8 — defesas da era agêntica (OWASP Agentic Top 10) ──────────────
    AuditEventType.GUARDRAIL_BLOCKED: [
        ("OWASP Agentic", "ASI01", "Agent Goal Hijacking"),
        ("OWASP LLM", "LLM01", "Prompt Injection"),
        ("NIST GenAI", "2.8", "Information Integrity"),
        ("EU AI Act GPAI", "Art.55", "Systemic Risk Mitigation"),
    ],
    AuditEventType.GUARDRAIL_FLAGGED: [
        ("OWASP Agentic", "ASI01", "Agent Goal Hijacking"),
        ("NIST GenAI", "2.4", "Data Privacy"),
    ],
    AuditEventType.TOOL_INTEGRITY_VIOLATION: [
        ("OWASP Agentic", "ASI06", "Tool Misuse & Exploitation"),
        ("OWASP Agentic", "ASI07", "Agentic Supply Chain"),
        ("NIST AI RMF", "MAP-4.1", "Third-party / Supply Chain Risk"),
    ],
    AuditEventType.MEMORY_QUARANTINED: [
        ("OWASP Agentic", "ASI09", "Memory & Context Poisoning"),
        ("NIST GenAI", "2.8", "Information Integrity"),
    ],
    AuditEventType.A2A_MESSAGE_REJECTED: [
        ("OWASP Agentic", "ASI04", "Insecure Inter-Agent Communication"),
        ("NIST AI RMF", "MANAGE-2.2", "Mechanisms to Sustain AI"),
    ],
}


class ComplianceReporter:
    """
    Gera evidências de compliance a partir do audit log.

    Uso típico (preparação para auditoria SOC2/ISO 42001):
        reporter = ComplianceReporter(audit_log_path)
        evidence = reporter.generate()
        print(evidence.render())
        Path("compliance_evidence.json").write_text(evidence.to_json())
    """

    def __init__(self, log_path: str | Path) -> None:
        self._logger = AuditLogger(log_path)

    def generate(self) -> ComplianceEvidence:
        events = self._logger.replay()
        chain_result = self._logger.verify_chain()

        if not events:
            return ComplianceEvidence(
                generated_at=datetime.now(UTC).isoformat(),
                audit_period_start=None,
                audit_period_end=None,
                total_events=0,
                chain_valid=chain_result.valid,
            )

        # Contagem por tipo de evento
        event_counts: dict[AuditEventType, int] = {}
        event_samples: dict[AuditEventType, list[dict[str, Any]]] = {}
        for event in events:
            et = event.event_type
            event_counts[et] = event_counts.get(et, 0) + 1
            if et not in event_samples:
                event_samples[et] = []
            if len(event_samples[et]) < 3:
                event_samples[et].append(
                    {
                        "sequence": event.sequence,
                        "timestamp": event.timestamp,
                        "agent_id": event.agent_id,
                        "tool_name": event.tool_name,
                    }
                )

        # Agrega evidências por controle
        control_evidence: dict[str, ControlEvidence] = {}
        for et, count in event_counts.items():
            for framework, control_id, control_name in _EVENT_CONTROLS.get(et, []):
                key = f"{framework}:{control_id}"
                if key not in control_evidence:
                    control_evidence[key] = ControlEvidence(
                        control_id=control_id,
                        control_name=control_name,
                        framework=framework,
                        status="IMPLEMENTED",
                        evidence_count=0,
                        description=f"Evidenciado por eventos de tipo '{et.value}'",
                        sample_events=[],
                    )
                control_evidence[key].evidence_count += count
                control_evidence[key].sample_events.extend(event_samples.get(et, [])[:2])

        return ComplianceEvidence(
            generated_at=datetime.now(UTC).isoformat(),
            audit_period_start=events[0].timestamp if events else None,
            audit_period_end=events[-1].timestamp if events else None,
            total_events=len(events),
            chain_valid=chain_result.valid,
            controls=sorted(
                control_evidence.values(),
                key=lambda c: (c.framework, c.control_id),
            ),
            summary={et.value: count for et, count in event_counts.items()},
        )
