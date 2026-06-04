"""
Audit logger append-only com encadeamento de hash.

Cada entrada inclui o hash SHA-256 da entrada anterior, formando uma cadeia
verificável. Adulteração de qualquer entrada invalida toda a cadeia subsequente.

Formato: JSONL (uma linha JSON por evento), gravado em append mode.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field


class AuditEventType(str, Enum):
    POLICY_DECISION = "policy_decision"
    ACTION_EXECUTED = "action_executed"
    ACTION_DENIED = "action_denied"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_DENIED = "approval_denied"
    BUDGET_EXCEEDED = "budget_exceeded"
    KILL_SWITCH_ACTIVATED = "kill_switch_activated"
    KILL_SWITCH_TRIGGERED = "kill_switch_triggered"
    CREDENTIAL_ISSUED = "credential_issued"
    CREDENTIAL_REVOKED = "credential_revoked"
    AGENT_REGISTERED = "agent_registered"
    DELEGATION_CREATED = "delegation_created"
    ERROR = "error"


class AuditEvent(BaseModel):
    """Um evento de auditoria imutável."""

    sequence: int
    event_type: AuditEventType
    timestamp: str  # ISO 8601 UTC
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    tool_name: Optional[str] = None
    environment: Optional[str] = None
    details: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str  # hash da entrada anterior (ou "GENESIS" para a primeira)
    entry_hash: str = ""  # preenchido pelo logger após construção

    def compute_hash(self) -> str:
        """Calcula o hash SHA-256 desta entrada (excluindo o campo entry_hash)."""
        data = self.model_dump(exclude={"entry_hash"})
        serialized = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode()).hexdigest()


class ChainVerificationResult(BaseModel):
    valid: bool
    total_entries: int
    first_broken_at: Optional[int] = None
    error: Optional[str] = None


class AuditLogger:
    """
    Logger de auditoria append-only com encadeamento de hash.

    Instanciar com um caminho de arquivo; o arquivo é criado se não existir.
    """

    GENESIS_HASH = "0" * 64  # hash sentinela para o primeiro registro

    def __init__(self, log_path: str | Path) -> None:
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        self._sequence = 0
        self._last_hash = self.GENESIS_HASH
        self._in_memory: list[AuditEvent] = []

        # Reconstitui estado a partir de arquivo existente
        if self._log_path.exists():
            self._replay_existing()

    def _replay_existing(self) -> None:
        """Lê entradas existentes para obter o estado atual da cadeia."""
        with open(self._log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    event = AuditEvent(**data)
                    self._sequence = event.sequence
                    self._last_hash = event.entry_hash
                    self._in_memory.append(event)
                except Exception:
                    # Linha corrompida — registra mas não para
                    pass

    def log(
        self,
        event_type: AuditEventType,
        agent_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        tool_name: Optional[str] = None,
        environment: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> AuditEvent:
        """Registra um evento na trilha de auditoria."""
        self._sequence += 1
        event = AuditEvent(
            sequence=self._sequence,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent_id=agent_id,
            agent_name=agent_name,
            tool_name=tool_name,
            environment=environment,
            details=details or {},
            previous_hash=self._last_hash,
        )
        event.entry_hash = event.compute_hash()
        self._last_hash = event.entry_hash
        self._in_memory.append(event)

        # Escreve em modo append — nunca sobrescreve
        with open(self._log_path, "a") as f:
            f.write(event.model_dump_json() + "\n")

        return event

    def verify_chain(self) -> ChainVerificationResult:
        """
        Verifica a integridade da cadeia de hashes.

        Reconstrói o hash de cada entrada e verifica se bate com o registrado.
        Qualquer divergência indica adulteração ou corrupção.
        """
        entries = self._load_all_entries()
        if not entries:
            return ChainVerificationResult(valid=True, total_entries=0)

        expected_prev = self.GENESIS_HASH
        for i, event in enumerate(entries):
            if event.previous_hash != expected_prev:
                return ChainVerificationResult(
                    valid=False,
                    total_entries=len(entries),
                    first_broken_at=event.sequence,
                    error=(
                        f"Entrada #{event.sequence}: previous_hash não bate. "
                        f"Esperado: {expected_prev[:16]}..., "
                        f"Encontrado: {event.previous_hash[:16]}..."
                    ),
                )
            recomputed = event.compute_hash()
            if recomputed != event.entry_hash:
                return ChainVerificationResult(
                    valid=False,
                    total_entries=len(entries),
                    first_broken_at=event.sequence,
                    error=(
                        f"Entrada #{event.sequence}: hash adulterado. "
                        f"Registrado: {event.entry_hash[:16]}..., "
                        f"Recomputado: {recomputed[:16]}..."
                    ),
                )
            expected_prev = event.entry_hash

        return ChainVerificationResult(valid=True, total_entries=len(entries))

    def _load_all_entries(self) -> list[AuditEvent]:
        """Carrega todas as entradas do arquivo de log."""
        if not self._log_path.exists():
            return []
        entries = []
        with open(self._log_path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(AuditEvent(**json.loads(line)))
                    except Exception:
                        pass
        return entries

    def replay(self) -> list[AuditEvent]:
        """Retorna todos os eventos em ordem cronológica (para replay/análise)."""
        return self._load_all_entries()

    def get_events_for_agent(self, agent_id: str) -> list[AuditEvent]:
        """Filtra eventos de um agente específico."""
        return [e for e in self.replay() if e.agent_id == agent_id]

    def clear(self) -> None:
        """Remove o arquivo de log (usado apenas em testes)."""
        if self._log_path.exists():
            os.remove(self._log_path)
        self._sequence = 0
        self._last_hash = self.GENESIS_HASH
        self._in_memory.clear()
