"""
Modelos de identidade para agentes de IA governados.

Cada agente possui identidade própria com escopos explicitamente concedidos.
A cadeia de delegação rastreia toda transferência de autoridade.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class AgentEnvironment(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class AgentScope(str, Enum):
    """Escopos de capacidade que podem ser concedidos a um agente."""

    READ_FILES = "read:files"
    WRITE_FILES = "write:files"
    DELETE_FILES = "delete:files"

    READ_DATABASE = "read:database"
    WRITE_DATABASE = "write:database"

    SEND_EMAIL = "send:email"
    SEND_NOTIFICATION = "send:notification"

    CALL_EXTERNAL_API = "call:external_api"
    CALL_INTERNAL_API = "call:internal_api"

    SPAWN_SUBAGENT = "spawn:subagent"
    MANAGE_AGENTS = "manage:agents"

    EXECUTE_CODE = "execute:code"

    READ_SECRETS = "read:secrets"


class AgentCredential(BaseModel):
    """Token de curta duração emitido para um agente autenticar-se no runtime."""

    token: str = Field(default_factory=lambda: secrets.token_hex(32))
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None

    @model_validator(mode="after")
    def validate_expiry(self) -> "AgentCredential":
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at")
        return self

    def is_valid(self) -> bool:
        """Retorna True se o token ainda é válido (não expirado e não revogado)."""
        if self.revoked:
            return False
        return datetime.now(timezone.utc) < self.expires_at

    def revoke(self, reason: str = "manual revocation") -> None:
        self.revoked = True
        self.revoked_at = datetime.now(timezone.utc)
        self.revoked_reason = reason


class AgentIdentity(BaseModel):
    """
    Identidade completa de um agente de IA.

    Um agente nasce sem escopos; toda capacidade é concedida explicitamente.
    """

    id: str
    name: str
    owner: str  # e-mail ou ID do humano responsável
    environment: AgentEnvironment
    scopes: list[AgentScope] = Field(default_factory=list)
    parent_id: Optional[str] = None  # ID do agente pai, quando sub-agente
    version: str = "1.0.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    credential: Optional[AgentCredential] = None

    def has_scope(self, scope: AgentScope) -> bool:
        return scope in self.scopes

    def has_any_scope(self, scopes: list[AgentScope]) -> bool:
        return any(s in self.scopes for s in scopes)

    def issue_credential(self, ttl_seconds: int = 3600) -> AgentCredential:
        """Emite um novo token de curta duração para este agente."""
        cred = AgentCredential(
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        )
        self.credential = cred
        return cred

    def revoke_credential(self, reason: str = "manual revocation") -> None:
        if self.credential:
            self.credential.revoke(reason)

    def is_authenticated(self) -> bool:
        """Verifica se o agente possui credencial válida."""
        return self.credential is not None and self.credential.is_valid()


class DelegationLink(BaseModel):
    """Um elo na cadeia de delegação de autoridade."""

    from_id: str  # quem delegou (humano ou agente)
    from_name: str
    to_id: str  # quem recebeu a delegação
    to_name: str
    delegated_scopes: list[AgentScope]
    delegated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str = ""

    def __str__(self) -> str:
        scopes = ", ".join(s.value for s in self.delegated_scopes)
        return f"{self.from_name} → {self.to_name} [{scopes}]"


class DelegationChain(BaseModel):
    """
    Cadeia completa de delegação: humano → agente → sub-agente.

    Um sub-agente só pode receber escopos que o delegante já possui —
    nunca pode escalar privilégios além do que a cadeia permite.
    """

    links: list[DelegationLink] = Field(default_factory=list)

    def add_link(
        self,
        delegator: AgentIdentity | str,
        delegatee: AgentIdentity,
        scopes: list[AgentScope],
        reason: str = "",
    ) -> DelegationLink:
        """
        Adiciona um elo à cadeia.

        Se `delegator` é um AgentIdentity, verifica que ele possui os escopos
        que está tentando delegar (prevenção de escalada de privilégio).
        """
        if isinstance(delegator, AgentIdentity):
            unauthorized = [s for s in scopes if not delegator.has_scope(s)]
            if unauthorized:
                bad = ", ".join(s.value for s in unauthorized)
                raise PermissionError(
                    f"Agente '{delegator.name}' tentou delegar escopos que não possui: {bad}"
                )
            from_id = delegator.id
            from_name = delegator.name
        else:
            # delegador é um humano (string com nome/e-mail)
            from_id = f"human:{delegator}"
            from_name = delegator

        link = DelegationLink(
            from_id=from_id,
            from_name=from_name,
            to_id=delegatee.id,
            to_name=delegatee.name,
            delegated_scopes=scopes,
            reason=reason,
        )
        self.links.append(link)
        return link

    def get_effective_scopes(self, agent_id: str) -> list[AgentScope]:
        """Retorna os escopos que foram delegados a um agente específico."""
        scopes: set[AgentScope] = set()
        for link in self.links:
            if link.to_id == agent_id:
                scopes.update(link.delegated_scopes)
        return list(scopes)

    def render(self) -> str:
        """Representação legível da cadeia para logs e relatórios."""
        if not self.links:
            return "(cadeia vazia)"
        return " | ".join(str(link) for link in self.links)
