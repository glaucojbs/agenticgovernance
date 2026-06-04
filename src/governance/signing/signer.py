"""
Assinatura criptográfica Ed25519 para o audit log.

Cada entrada do log é assinada com a chave privada do serviço.
A verificação usa apenas a chave pública — que pode ser distribuída
para auditores externos sem expor a chave privada.

Vantagem sobre hash chain puro:
  - Hash chain: detecta adulteração, mas atacante com acesso ao disco
    pode recriar toda a cadeia com novos hashes.
  - Ed25519: sem a chave privada, impossível forjar uma assinatura válida.
    A chave privada fica num HSM (produção) ou arquivo protegido (dev).

Em produção:
  - Chave privada: AWS KMS / GCP KMS / HashiCorp Vault (nunca em disco)
  - Chave pública: distribuída para auditores, armazenada em Git
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from governance.audit.logger import AuditEvent, AuditEventType, AuditLogger


class AuditSigner:
    """
    Assina e verifica entradas de auditoria com Ed25519.

    Uso típico:
        signer = AuditSigner.generate()          # dev / primeiro boot
        signer.save_keys("keys/audit_private.pem", "keys/audit_public.pem")

    Em produção, carregar da KMS:
        private_pem = vault_client.get_secret("audit-signing-key")
        signer = AuditSigner.from_pem(private_pem)
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> AuditSigner:
        """Gera um novo par de chaves Ed25519."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem_file(cls, private_key_path: str | Path) -> AuditSigner:
        """Carrega a chave privada de um arquivo PEM."""
        pem = Path(private_key_path).read_bytes()
        key = load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("Arquivo não contém chave Ed25519 privada")
        return cls(key)

    @classmethod
    def from_pem(cls, private_pem: bytes) -> AuditSigner:
        """Carrega a chave privada de bytes PEM (ex.: vindo de Vault)."""
        key = load_pem_private_key(private_pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("PEM não contém chave Ed25519 privada")
        return cls(key)

    def save_keys(
        self,
        private_path: str | Path,
        public_path: str | Path,
    ) -> None:
        """Salva o par de chaves em arquivos PEM."""
        Path(private_path).parent.mkdir(parents=True, exist_ok=True)
        Path(private_path).write_bytes(
            self._private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        )
        Path(public_path).parent.mkdir(parents=True, exist_ok=True)
        Path(public_path).write_bytes(
            self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )

    def public_key_pem(self) -> str:
        """Retorna a chave pública em formato PEM (para distribuir a auditores)."""
        return self._public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def sign_entry(self, event: AuditEvent) -> str:
        """Assina uma entrada de auditoria e retorna a assinatura em base64."""
        payload = json.dumps(
            event.model_dump(exclude={"entry_hash"}),
            sort_keys=True,
            default=str,
        ).encode()
        sig_bytes = self._private_key.sign(payload)
        return base64.b64encode(sig_bytes).decode()

    @classmethod
    def verify_entry(
        cls,
        event: AuditEvent,
        signature_b64: str,
        public_key_pem: bytes | str,
    ) -> bool:
        """Verifica a assinatura de uma entrada usando a chave pública."""
        if isinstance(public_key_pem, str):
            public_key_pem = public_key_pem.encode()
        pub_key = load_pem_public_key(public_key_pem)
        if not isinstance(pub_key, Ed25519PublicKey):
            raise ValueError("PEM não contém chave Ed25519 pública")
        payload = json.dumps(
            event.model_dump(exclude={"entry_hash"}),
            sort_keys=True,
            default=str,
        ).encode()
        try:
            pub_key.verify(base64.b64decode(signature_b64), payload)
            return True
        except Exception:
            return False


class SignedAuditLogger(AuditLogger):
    """
    AuditLogger com assinatura Ed25519 em cada entrada.

    Estende AuditLogger: mantém toda a funcionalidade (hash chain,
    append-only, verify_chain) e adiciona o campo `signature` em cada
    entrada do JSONL.

    Formato de cada linha:
        {"sequence": 1, ..., "entry_hash": "...", "signature": "<base64>"}
    """

    def __init__(
        self,
        log_path: str | Path,
        signer: AuditSigner,
    ) -> None:
        self._signer = signer
        super().__init__(log_path)

    def log(
        self,
        event_type: AuditEventType,
        agent_id: str | None = None,
        agent_name: str | None = None,
        tool_name: str | None = None,
        environment: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Registra um evento e adiciona assinatura Ed25519."""
        event = super().log(
            event_type,
            agent_id=agent_id,
            agent_name=agent_name,
            tool_name=tool_name,
            environment=environment,
            details=details,
        )
        # Assina e adiciona ao dict antes de re-escrever a última linha
        # (leitura eficiente: apenas sobrescreve a última linha — já foi escrita pelo super)
        signature = self._signer.sign_entry(event)
        # Anexa a assinatura re-escrevendo só o último registro no arquivo
        self._rewrite_last_entry_with_signature(event, signature)
        return event

    def _rewrite_last_entry_with_signature(
        self, event: AuditEvent, signature: str
    ) -> None:
        """Lê o arquivo, substitui a última linha pela versão assinada."""
        try:
            content = self._log_path.read_text()
            lines = [ln for ln in content.splitlines() if ln.strip()]
            if not lines:
                return
            # Substitui a última linha pelo dict com assinatura
            data = json.loads(lines[-1])
            data["signature"] = signature
            lines[-1] = json.dumps(data)
            self._log_path.write_text("\n".join(lines) + "\n")
        except Exception:
            # Nunca deixar a assinatura comprometer a escrita do log
            pass

    def verify_signatures(self, public_key_pem: bytes | str) -> dict[str, Any]:
        """
        Verifica todas as assinaturas do log.

        Retorna:
          {valid: bool, total: int, invalid_entries: [seq_numbers]}
        """
        import json as _json

        invalid: list[int] = []
        total = 0

        with open(self._log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = _json.loads(line)
                    sig = data.pop("signature", None)
                    event = AuditEvent(**data)
                    total += 1
                    if not sig or not AuditSigner.verify_entry(event, sig, public_key_pem):
                        invalid.append(event.sequence)
                except Exception:
                    pass

        return {
            "valid": len(invalid) == 0,
            "total": total,
            "invalid_entries": invalid,
        }
