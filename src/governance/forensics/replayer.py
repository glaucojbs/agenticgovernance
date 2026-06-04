"""
IncidentReplayer — reconstrução forense de incidentes.

A partir de um audit log (JSONL + hash chain), reconstrói:
  - Timeline completa de eventos por agente
  - Primeira ocorrência de cada ferramenta por agente
  - Sequências suspeitas (N negações seguidas, escalada, etc.)
  - Janelas de atividade (quando o agente estava ativo)
  - Resumo de impacto: o que foi efetivamente executado

Usado durante incident response para responder:
  "O que exatamente o agente fez entre 14h e 15h?"
  "Quais dados foram acessados antes do kill switch?"
  "Houve tentativas de escalada de privilégio?"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from governance.audit.logger import AuditEventType, AuditLogger


@dataclass
class TimelineEntry:
    sequence: int
    timestamp: str
    event_type: str
    agent_id: str
    agent_name: str
    tool_name: str
    success: bool
    details: dict[str, Any]


@dataclass
class IncidentTimeline:
    """Timeline reconstruída de um ou mais agentes."""
    entries: list[TimelineEntry] = field(default_factory=list)
    agent_ids: list[str] = field(default_factory=list)

    # Estatísticas
    total_events: int = 0
    executed_actions: int = 0
    denied_actions: int = 0
    approved_actions: int = 0
    kill_switch_triggers: int = 0
    budget_exceeded: int = 0
    first_event_ts: str | None = None
    last_event_ts: str | None = None

    # Padrões detectados
    first_tool_use: dict[str, str] = field(default_factory=dict)   # tool → timestamp
    consecutive_deny_windows: list[dict[str, Any]] = field(default_factory=list)
    tools_executed: list[str] = field(default_factory=list)
    tools_attempted_denied: list[str] = field(default_factory=list)

    def render_timeline(self, max_entries: int = 50) -> str:
        lines = [
            "╔" + "═" * 70 + "╗",
            "║  INCIDENT TIMELINE RECONSTRUCTION" + " " * 35 + "║",
            "╠" + "═" * 70 + "╣",
            f"║  Agentes : {', '.join(self.agent_ids):<58}║",
            f"║  Período : {(self.first_event_ts or '?')[11:19]} → {(self.last_event_ts or '?')[11:19]:<49}║",
            f"║  Eventos : {self.total_events:<59}║",
            "╠" + "═" * 70 + "╣",
        ]

        icon_map = {
            AuditEventType.ACTION_EXECUTED: "✓",
            AuditEventType.ACTION_DENIED: "✗",
            AuditEventType.APPROVAL_GRANTED: "✓🔐",
            AuditEventType.APPROVAL_DENIED: "✗🔐",
            AuditEventType.KILL_SWITCH_TRIGGERED: "🚨",
            AuditEventType.BUDGET_EXCEEDED: "💰",
            AuditEventType.POLICY_DECISION: "📋",
            AuditEventType.APPROVAL_REQUESTED: "⏳",
        }

        shown = self.entries[-max_entries:] if len(self.entries) > max_entries else self.entries
        for entry in shown:
            icon = icon_map.get(entry.event_type, "·")
            ts = entry.timestamp[11:19] if entry.timestamp else "??:??:??"
            tool = (entry.tool_name or "-")[:20]
            agent = (entry.agent_name or "-")[:16]
            decision = entry.details.get("decision", "")
            line = f"║  [{ts}] {icon:<4} {agent:<16} {tool:<20} {decision:<8}║"
            lines.append(line)

        lines += [
            "╠" + "═" * 70 + "╣",
            f"║  Executadas  : {self.executed_actions:<54}║",
            f"║  Negadas     : {self.denied_actions:<54}║",
            f"║  Kill switch : {self.kill_switch_triggers:<54}║",
            f"║  Orçamento   : {self.budget_exceeded:<54}║",
        ]
        if self.tools_executed:
            tools_str = ", ".join(sorted(set(self.tools_executed)))[:54]
            lines.append(f"║  Executadas  : {tools_str:<54}║")
        if self.tools_attempted_denied:
            denied_str = ", ".join(sorted(set(self.tools_attempted_denied)))[:54]
            lines.append(f"║  Tentativas  : {denied_str:<54}║")
        if self.consecutive_deny_windows:
            lines.append(f"║  ⚠ Janelas de negação consecutiva: {len(self.consecutive_deny_windows):<34}║")
        lines.append("╚" + "═" * 70 + "╝")
        return "\n".join(lines)


class IncidentReplayer:
    """
    Reconstrói a timeline forense a partir de um arquivo de audit log.

    Verifica a integridade da chain antes de produzir o relatório.
    """

    def __init__(self, log_path: str | Path) -> None:
        self._log_path = Path(log_path)
        self._logger = AuditLogger(log_path)

    def verify_integrity(self) -> tuple[bool, str]:
        """Verifica integridade antes de analisar. Retorna (ok, mensagem)."""
        result = self._logger.verify_chain()
        if result.valid:
            return True, f"Chain válida — {result.total_entries} entradas verificadas"
        return False, f"ADULTERAÇÃO DETECTADA na entrada #{result.first_broken_at}: {result.error}"

    def replay(
        self,
        agent_ids: list[str] | None = None,
        since_ts: str | None = None,
        until_ts: str | None = None,
        event_types: list[AuditEventType] | None = None,
    ) -> IncidentTimeline:
        """
        Reconstrói a timeline com filtros opcionais.

        Args:
            agent_ids: filtrar por agentes específicos (None = todos)
            since_ts: ISO timestamp mínimo
            until_ts: ISO timestamp máximo
            event_types: filtrar por tipos de evento
        """
        events = self._logger.replay()
        timeline = IncidentTimeline()
        consecutive_denies = 0
        deny_window_start: str | None = None

        for event in events:
            # Filtros
            if agent_ids and event.agent_id not in agent_ids:
                continue
            if since_ts and event.timestamp < since_ts:
                continue
            if until_ts and event.timestamp > until_ts:
                continue
            if event_types and event.event_type not in event_types:
                continue

            # Atualiza agentes únicos
            if event.agent_id and event.agent_id not in timeline.agent_ids:
                timeline.agent_ids.append(event.agent_id)

            # Período
            if timeline.first_event_ts is None:
                timeline.first_event_ts = event.timestamp
            timeline.last_event_ts = event.timestamp

            # Estatísticas
            timeline.total_events += 1
            et = event.event_type

            if et == AuditEventType.ACTION_EXECUTED:
                timeline.executed_actions += 1
                if event.tool_name:
                    timeline.tools_executed.append(event.tool_name)
                consecutive_denies = 0
                deny_window_start = None
                # Registra primeira vez que a ferramenta foi usada
                if event.tool_name and event.tool_name not in timeline.first_tool_use:
                    timeline.first_tool_use[event.tool_name] = event.timestamp

            elif et == AuditEventType.ACTION_DENIED:
                timeline.denied_actions += 1
                if event.tool_name:
                    timeline.tools_attempted_denied.append(event.tool_name)
                consecutive_denies += 1
                if consecutive_denies == 1:
                    deny_window_start = event.timestamp
                if consecutive_denies >= 3 and deny_window_start:
                    # Registra janela de negações consecutivas suspeitas
                    timeline.consecutive_deny_windows.append({
                        "start": deny_window_start,
                        "end": event.timestamp,
                        "count": consecutive_denies,
                        "agent_id": event.agent_id,
                    })

            elif et == AuditEventType.APPROVAL_GRANTED:
                timeline.approved_actions += 1
                consecutive_denies = 0

            elif et == AuditEventType.KILL_SWITCH_TRIGGERED:
                timeline.kill_switch_triggers += 1

            elif et == AuditEventType.BUDGET_EXCEEDED:
                timeline.budget_exceeded += 1

            # Entrada na timeline
            success = et in (
                AuditEventType.ACTION_EXECUTED,
                AuditEventType.APPROVAL_GRANTED,
            )
            timeline.entries.append(TimelineEntry(
                sequence=event.sequence,
                timestamp=event.timestamp,
                event_type=et,
                agent_id=event.agent_id or "",
                agent_name=event.agent_name or "",
                tool_name=event.tool_name or "",
                success=success,
                details=event.details,
            ))

        return timeline

    def find_first_occurrence(self, tool_name: str) -> TimelineEntry | None:
        """Encontra a primeira vez que uma ferramenta foi usada (sucesso)."""
        for event in self._logger.replay():
            if (
                event.event_type == AuditEventType.ACTION_EXECUTED
                and event.tool_name == tool_name
            ):
                return TimelineEntry(
                    sequence=event.sequence,
                    timestamp=event.timestamp,
                    event_type=event.event_type,
                    agent_id=event.agent_id or "",
                    agent_name=event.agent_name or "",
                    tool_name=event.tool_name or "",
                    success=True,
                    details=event.details,
                )
        return None

    def agent_activity_summary(self, agent_id: str) -> dict[str, Any]:
        """Resumo de atividade de um agente específico."""
        events = self._logger.get_events_for_agent(agent_id)
        executed = [e for e in events if e.event_type == AuditEventType.ACTION_EXECUTED]
        denied = [e for e in events if e.event_type == AuditEventType.ACTION_DENIED]
        return {
            "agent_id": agent_id,
            "total_events": len(events),
            "executed": len(executed),
            "denied": len(denied),
            "deny_rate": len(denied) / len(events) if events else 0.0,
            "tools_executed": list({e.tool_name for e in executed if e.tool_name}),
            "tools_denied": list({e.tool_name for e in denied if e.tool_name}),
            "first_event": events[0].timestamp if events else None,
            "last_event": events[-1].timestamp if events else None,
        }
