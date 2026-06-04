"""Gerenciador central de identidades de agentes."""

from __future__ import annotations

from governance.identity.models import AgentCredential, AgentIdentity, AgentScope


class IdentityManager:
    """
    Registro em memória de identidades de agentes.

    Em produção, substituir pelo backend de identidade da organização
    (ex.: SPIFFE Workload API, Vault, AWS IAM Roles Anywhere).
    """

    def __init__(self) -> None:
        self._identities: dict[str, AgentIdentity] = {}

    def register(self, identity: AgentIdentity) -> AgentIdentity:
        """Registra um agente e emite sua credencial inicial."""
        if identity.id in self._identities:
            raise ValueError(f"Agente '{identity.id}' já registrado")
        identity.issue_credential()
        self._identities[identity.id] = identity
        return identity

    def get(self, agent_id: str) -> AgentIdentity | None:
        return self._identities.get(agent_id)

    def revoke(self, agent_id: str, reason: str = "manual revocation") -> None:
        identity = self._identities.get(agent_id)
        if identity:
            identity.revoke_credential(reason)

    def validate_credential(self, agent_id: str, token: str) -> bool:
        """Verifica se o token apresentado é válido para o agente."""
        identity = self._identities.get(agent_id)
        if not identity or not identity.credential:
            return False
        return identity.credential.token == token and identity.credential.is_valid()

    def grant_scope(self, agent_id: str, scope: AgentScope) -> None:
        identity = self._identities.get(agent_id)
        if not identity:
            raise ValueError(f"Agente '{agent_id}' não encontrado")
        if scope not in identity.scopes:
            identity.scopes.append(scope)

    def revoke_scope(self, agent_id: str, scope: AgentScope) -> None:
        identity = self._identities.get(agent_id)
        if identity and scope in identity.scopes:
            identity.scopes.remove(scope)

    def list_agents(self) -> list[AgentIdentity]:
        return list(self._identities.values())

    def renew_credential(self, agent_id: str, ttl_seconds: int = 3600) -> AgentCredential:
        identity = self._identities.get(agent_id)
        if not identity:
            raise ValueError(f"Agente '{agent_id}' não encontrado")
        return identity.issue_credential(ttl_seconds)
