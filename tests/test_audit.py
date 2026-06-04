"""Testes para o audit logger com hash encadeado."""

import json
import tempfile
from pathlib import Path

import pytest

from governance.audit.logger import AuditEventType, AuditLogger


@pytest.fixture()
def tmp_log(tmp_path: Path) -> Path:
    return tmp_path / "test_audit.jsonl"


@pytest.fixture()
def logger(tmp_log: Path) -> AuditLogger:
    return AuditLogger(tmp_log)


class TestAuditLogger:
    def test_first_event_uses_genesis_hash(self, logger: AuditLogger) -> None:
        event = logger.log(AuditEventType.ACTION_EXECUTED, agent_id="a1")
        assert event.previous_hash == AuditLogger.GENESIS_HASH
        assert event.sequence == 1

    def test_chain_links_correctly(self, logger: AuditLogger) -> None:
        e1 = logger.log(AuditEventType.ACTION_EXECUTED)
        e2 = logger.log(AuditEventType.ACTION_DENIED)
        assert e2.previous_hash == e1.entry_hash
        assert e2.sequence == 2

    def test_verify_chain_passes_for_intact_log(self, logger: AuditLogger) -> None:
        for i in range(5):
            logger.log(AuditEventType.ACTION_EXECUTED, agent_id=f"agent-{i}")
        result = logger.verify_chain()
        assert result.valid
        assert result.total_entries == 5

    def test_verify_chain_empty_log(self, logger: AuditLogger) -> None:
        result = logger.verify_chain()
        assert result.valid
        assert result.total_entries == 0

    def test_tamper_detection(self, logger: AuditLogger, tmp_log: Path) -> None:
        logger.log(AuditEventType.ACTION_EXECUTED, agent_id="agent-1", details={"x": 1})
        logger.log(AuditEventType.ACTION_EXECUTED, agent_id="agent-2", details={"x": 2})

        # Adultera o arquivo diretamente
        lines = tmp_log.read_text().splitlines()
        data = json.loads(lines[0])
        data["details"]["x"] = 999  # modifica o conteúdo
        lines[0] = json.dumps(data)
        tmp_log.write_text("\n".join(lines) + "\n")

        # Reconstrói o logger a partir do arquivo adulterado
        tampered_logger = AuditLogger(tmp_log)
        result = tampered_logger.verify_chain()
        assert not result.valid
        assert result.first_broken_at is not None

    def test_replay_returns_all_events(self, logger: AuditLogger) -> None:
        logger.log(AuditEventType.POLICY_DECISION, agent_id="a1")
        logger.log(AuditEventType.ACTION_EXECUTED, agent_id="a1")
        logger.log(AuditEventType.APPROVAL_REQUESTED, agent_id="a2")
        events = logger.replay()
        assert len(events) == 3

    def test_filter_by_agent(self, logger: AuditLogger) -> None:
        logger.log(AuditEventType.ACTION_EXECUTED, agent_id="a1")
        logger.log(AuditEventType.ACTION_EXECUTED, agent_id="a2")
        logger.log(AuditEventType.ACTION_EXECUTED, agent_id="a1")
        events = logger.get_events_for_agent("a1")
        assert len(events) == 2
        assert all(e.agent_id == "a1" for e in events)

    def test_persistence_across_instances(self, tmp_log: Path) -> None:
        """Verifica que um novo logger lê o estado correto do arquivo existente."""
        logger1 = AuditLogger(tmp_log)
        e1 = logger1.log(AuditEventType.ACTION_EXECUTED)

        logger2 = AuditLogger(tmp_log)  # carrega do disco
        e2 = logger2.log(AuditEventType.POLICY_DECISION)

        # O hash anterior de e2 deve ser o hash de e1
        assert e2.previous_hash == e1.entry_hash
        assert logger2.verify_chain().valid
