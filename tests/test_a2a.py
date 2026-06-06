"""Testes do canal A2A assinado (autenticidade, escopo, expiração, replay)."""

import tempfile
from dataclasses import replace
from pathlib import Path

from governance.a2a.channel import CapabilityToken, SignedAgentChannel
from governance.audit.logger import AuditEventType, AuditLogger
from governance.signing.signer import AuditSigner


def _channel_with_sender(audit=None):
    channel = SignedAgentChannel(audit=audit)
    signer = AuditSigner.generate()
    channel.register_agent("sender", signer.public_key_pem())
    return channel, signer


class TestSignedAgentChannel:
    def test_valid_message_accepted(self):
        channel, signer = _channel_with_sender()
        msg = channel.send("sender", signer, "recv", {"task": "x"}, scopes=["read:database"])
        result = channel.receive(msg, required_scope="read:database")
        assert result.accepted

    def test_unregistered_sender_rejected(self):
        channel = SignedAgentChannel()
        signer = AuditSigner.generate()
        msg = channel.send("ghost", signer, "recv", {}, scopes=[])
        result = channel.receive(msg)
        assert not result.accepted
        assert "não registrado" in result.reason

    def test_tampered_signature_rejected(self):
        channel, signer = _channel_with_sender()
        msg = channel.send("sender", signer, "recv", {"task": "x"}, scopes=["read:database"])
        msg.payload["task"] = "TAMPERED"  # altera após assinar
        result = channel.receive(msg, required_scope="read:database")
        assert not result.accepted
        assert "assinatura" in result.reason

    def test_expired_token_rejected(self):
        channel, signer = _channel_with_sender()
        msg = channel.send("sender", signer, "recv", {"task": "x"}, scopes=["read:database"])
        # força expiração re-assinando uma cópia com token vencido
        expired = replace(
            msg.capability,
            issued_at="2000-01-01T00:00:00+00:00",
            expires_at="2000-01-01T00:01:00+00:00",
        )
        msg.capability = expired
        msg.signature = signer.sign_message(msg.signing_payload())
        result = channel.receive(msg, required_scope="read:database")
        assert not result.accepted
        assert "expirado" in result.reason

    def test_replay_rejected(self):
        channel, signer = _channel_with_sender()
        msg = channel.send("sender", signer, "recv", {"task": "x"}, scopes=["read:database"])
        assert channel.receive(msg, required_scope="read:database").accepted
        second = channel.receive(msg, required_scope="read:database")
        assert not second.accepted
        assert "replay" in second.reason

    def test_missing_scope_rejected(self):
        channel, signer = _channel_with_sender()
        msg = channel.send("sender", signer, "recv", {"task": "x"}, scopes=["read:database"])
        result = channel.receive(msg, required_scope="delete:files")
        assert not result.accepted
        assert "escopo" in result.reason

    def test_rejection_is_audited(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLogger(Path(tmp) / "a.jsonl")
            channel, signer = _channel_with_sender(audit=audit)
            msg = channel.send("sender", signer, "recv", {}, scopes=[])
            msg.signature = "invalid"
            channel.receive(msg)
            events = audit.replay()
            assert any(e.event_type == AuditEventType.A2A_MESSAGE_REJECTED for e in events)


class TestCapabilityToken:
    def test_has_scope(self):
        tok = CapabilityToken(scopes=["a", "b"], issued_at="x", expires_at="y")
        assert tok.has_scope("a")
        assert not tok.has_scope("c")
