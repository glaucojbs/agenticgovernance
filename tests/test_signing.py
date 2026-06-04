"""Testes para assinatura Ed25519 do audit log."""

import json
from datetime import UTC
from pathlib import Path

from governance.audit.logger import AuditEventType, AuditLogger
from governance.signing.signer import AuditSigner, SignedAuditLogger


class TestAuditSigner:
    def test_generate_and_sign(self) -> None:
        signer = AuditSigner.generate()
        logger = AuditLogger.__new__(AuditLogger)
        logger._sequence = 0
        logger._last_hash = AuditLogger.GENESIS_HASH
        logger._in_memory = []
        from datetime import datetime

        from governance.audit.logger import AuditEvent

        event = AuditEvent(
            sequence=1,
            event_type=AuditEventType.ACTION_EXECUTED,
            timestamp=datetime.now(UTC).isoformat(),
            previous_hash=AuditLogger.GENESIS_HASH,
        )
        event.entry_hash = event.compute_hash()
        sig = signer.sign_entry(event)
        assert sig  # não vazio
        assert AuditSigner.verify_entry(event, sig, signer.public_key_pem())

    def test_verify_tampered_entry_fails(self) -> None:
        signer = AuditSigner.generate()
        from datetime import datetime

        from governance.audit.logger import AuditEvent

        event = AuditEvent(
            sequence=1,
            event_type=AuditEventType.ACTION_EXECUTED,
            timestamp=datetime.now(UTC).isoformat(),
            previous_hash=AuditLogger.GENESIS_HASH,
            details={"x": 1},
        )
        event.entry_hash = event.compute_hash()
        sig = signer.sign_entry(event)
        # Adultera o evento
        event.details["x"] = 999
        assert not AuditSigner.verify_entry(event, sig, signer.public_key_pem())

    def test_save_and_load_keys(self, tmp_path: Path) -> None:
        signer = AuditSigner.generate()
        priv = tmp_path / "private.pem"
        pub = tmp_path / "public.pem"
        signer.save_keys(priv, pub)
        loaded = AuditSigner.from_pem_file(priv)
        assert loaded.public_key_pem() == signer.public_key_pem()


class TestSignedAuditLogger:
    def test_all_entries_signed(self, tmp_path: Path) -> None:
        signer = AuditSigner.generate()
        logger = SignedAuditLogger(tmp_path / "signed.jsonl", signer)
        for i in range(5):
            logger.log(AuditEventType.ACTION_EXECUTED, agent_id=f"a{i}")

        result = logger.verify_signatures(signer.public_key_pem())
        assert result["valid"]
        assert result["total"] == 5
        assert result["invalid_entries"] == []

    def test_hash_chain_still_valid(self, tmp_path: Path) -> None:
        signer = AuditSigner.generate()
        logger = SignedAuditLogger(tmp_path / "signed.jsonl", signer)
        for _ in range(5):
            logger.log(AuditEventType.POLICY_DECISION)
        chain = logger.verify_chain()
        assert chain.valid

    def test_tampered_signature_detected(self, tmp_path: Path) -> None:
        signer = AuditSigner.generate()
        log_path = tmp_path / "signed.jsonl"
        logger = SignedAuditLogger(log_path, signer)
        logger.log(AuditEventType.ACTION_EXECUTED)

        # Adultera a assinatura da primeira linha
        lines = log_path.read_text().splitlines()
        data = json.loads(lines[0])
        data["signature"] = "AAAA" + data["signature"][4:]
        lines[0] = json.dumps(data)
        log_path.write_text("\n".join(lines) + "\n")

        result = logger.verify_signatures(signer.public_key_pem())
        assert not result["valid"]
        assert 1 in result["invalid_entries"]
