"""Testes para o IncidentReplayer."""

from pathlib import Path

import pytest

from governance.audit.logger import AuditEventType, AuditLogger
from governance.forensics.replayer import IncidentReplayer


@pytest.fixture()
def log_with_incident(tmp_path: Path) -> Path:
    log = tmp_path / "incident.jsonl"
    logger = AuditLogger(log)
    # Atividade normal
    logger.log(
        AuditEventType.ACTION_EXECUTED, agent_id="agent-1", agent_name="A1", tool_name="read_files"
    )
    logger.log(
        AuditEventType.ACTION_EXECUTED, agent_id="agent-1", agent_name="A1", tool_name="read_files"
    )
    # Tentativas maliciosas
    for _ in range(4):
        logger.log(
            AuditEventType.ACTION_DENIED,
            agent_id="agent-1",
            agent_name="A1",
            tool_name="delete_files",
        )
    logger.log(
        AuditEventType.KILL_SWITCH_TRIGGERED,
        agent_id="agent-1",
        agent_name="A1",
        tool_name="read_files",
    )
    # Outro agente sem incidente
    logger.log(
        AuditEventType.ACTION_EXECUTED,
        agent_id="agent-2",
        agent_name="A2",
        tool_name="query_database",
    )
    return log


class TestIncidentReplayer:
    def test_verify_integrity_valid(self, log_with_incident: Path) -> None:
        r = IncidentReplayer(log_with_incident)
        ok, msg = r.verify_integrity()
        assert ok

    def test_replay_all_agents(self, log_with_incident: Path) -> None:
        r = IncidentReplayer(log_with_incident)
        timeline = r.replay()
        assert timeline.total_events == 8
        assert "agent-1" in timeline.agent_ids
        assert "agent-2" in timeline.agent_ids

    def test_replay_filter_by_agent(self, log_with_incident: Path) -> None:
        r = IncidentReplayer(log_with_incident)
        timeline = r.replay(agent_ids=["agent-1"])
        assert all(e.agent_id == "agent-1" for e in timeline.entries)
        assert timeline.kill_switch_triggers == 1

    def test_consecutive_deny_window_detected(self, log_with_incident: Path) -> None:
        r = IncidentReplayer(log_with_incident)
        timeline = r.replay(agent_ids=["agent-1"])
        assert len(timeline.consecutive_deny_windows) > 0
        assert timeline.denied_actions == 4

    def test_agent_activity_summary(self, log_with_incident: Path) -> None:
        r = IncidentReplayer(log_with_incident)
        summary = r.agent_activity_summary("agent-1")
        assert summary["executed"] == 2
        assert summary["denied"] == 4
        assert summary["deny_rate"] == pytest.approx(4 / 7)

    def test_find_first_occurrence(self, log_with_incident: Path) -> None:
        r = IncidentReplayer(log_with_incident)
        entry = r.find_first_occurrence("read_files")
        assert entry is not None
        assert entry.tool_name == "read_files"
