"""
Canal A2A assinado — autenticidade, autorização e anti-replay entre agentes.

Cada mensagem:
  - é assinada com a chave Ed25519 do remetente (autenticidade + integridade);
  - carrega um CapabilityToken com escopos e validade (autorização mínima);
  - tem um nonce único (proteção contra replay).

O receptor valida, nessa ordem: remetente registrado → assinatura → expiração →
nonce não reutilizado → escopo exigido presente.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from governance.signing.signer import AuditSigner

if TYPE_CHECKING:
    from governance.audit.logger import AuditLogger


@dataclass
class CapabilityToken:
    """Token de capacidade com escopo e validade (delegação mínima)."""

    scopes: list[str]
    issued_at: str
    expires_at: str

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return now >= datetime.fromisoformat(self.expires_at)

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass
class AgentMessage:
    """Mensagem assinada trocada entre dois agentes."""

    message_id: str
    sender_id: str
    recipient_id: str
    payload: dict[str, Any]
    nonce: str
    capability: CapabilityToken
    signature: str = ""

    def signing_payload(self) -> str:
        """Representação canônica e determinística para assinar/verificar."""
        data = {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "payload": self.payload,
            "nonce": self.nonce,
            "capability": asdict(self.capability),
        }
        return json.dumps(data, sort_keys=True, default=str)


@dataclass
class ReceiveResult:
    accepted: bool
    reason: str = ""
    message: AgentMessage | None = None


class SignedAgentChannel:
    """Roteia mensagens A2A assinadas entre agentes registrados.

    Uso:
        channel = SignedAgentChannel()
        channel.register_agent("orchestrator", orch_signer.public_key_pem())
        msg = channel.send("orchestrator", orch_signer, "worker",
                           {"task": "fetch"}, scopes=["read:database"])
        result = channel.receive(msg, required_scope="read:database")
    """

    def __init__(self, audit: AuditLogger | None = None) -> None:
        self._public_keys: dict[str, str] = {}
        self._seen_nonces: set[str] = set()
        self._audit = audit

    def register_agent(self, agent_id: str, public_key_pem: str) -> None:
        """Registra a chave pública de um agente para verificação de mensagens."""
        self._public_keys[agent_id] = public_key_pem

    def send(
        self,
        sender_id: str,
        signer: AuditSigner,
        recipient_id: str,
        payload: dict[str, Any],
        scopes: list[str],
        ttl_seconds: int = 300,
    ) -> AgentMessage:
        """Cria e assina uma mensagem A2A."""
        now = datetime.now(UTC)
        capability = CapabilityToken(
            scopes=list(scopes),
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=ttl_seconds)).isoformat(),
        )
        message = AgentMessage(
            message_id=secrets.token_hex(8),
            sender_id=sender_id,
            recipient_id=recipient_id,
            payload=payload,
            nonce=secrets.token_hex(16),
            capability=capability,
        )
        message.signature = signer.sign_message(message.signing_payload())
        return message

    def receive(
        self,
        message: AgentMessage,
        required_scope: str | None = None,
    ) -> ReceiveResult:
        """Valida uma mensagem recebida. Rejeições são auditadas."""
        public_pem = self._public_keys.get(message.sender_id)
        if public_pem is None:
            return self._reject(message, "remetente não registrado")

        if not AuditSigner.verify_message(message.signing_payload(), message.signature, public_pem):
            return self._reject(message, "assinatura inválida")

        if message.capability.is_expired():
            return self._reject(message, "token de capacidade expirado")

        if message.nonce in self._seen_nonces:
            return self._reject(message, "nonce já utilizado — possível replay")

        if required_scope is not None and not message.capability.has_scope(required_scope):
            return self._reject(message, f"escopo exigido '{required_scope}' ausente no token")

        # Aceita: consome o nonce para impedir replay futuro
        self._seen_nonces.add(message.nonce)
        return ReceiveResult(accepted=True, message=message)

    def _reject(self, message: AgentMessage, reason: str) -> ReceiveResult:
        if self._audit is not None:
            from governance.audit.logger import AuditEventType

            self._audit.log(
                AuditEventType.A2A_MESSAGE_REJECTED,
                agent_id=message.sender_id,
                details={
                    "message_id": message.message_id,
                    "recipient_id": message.recipient_id,
                    "reason": reason,
                },
            )
        return ReceiveResult(accepted=False, reason=reason)
