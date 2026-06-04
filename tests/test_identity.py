"""Testes para o subsistema de identidade."""

import time
from datetime import datetime, timedelta, timezone

import pytest

from governance.identity.models import (
    AgentCredential,
    AgentEnvironment,
    AgentIdentity,
    AgentScope,
    DelegationChain,
)
from governance.identity.manager import IdentityManager


def make_identity(
    agent_id: str = "agent-001",
    scopes: list[AgentScope] | None = None,
    env: AgentEnvironment = AgentEnvironment.DEV,
) -> AgentIdentity:
    return AgentIdentity(
        id=agent_id,
        name="Test Agent",
        owner="owner@example.com",
        environment=env,
        scopes=scopes or [],
    )


# ── Credential ─────────────────────────────────────────────────────────────

class TestAgentCredential:
    def test_fresh_credential_is_valid(self) -> None:
        cred = AgentCredential(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        assert cred.is_valid()

    def test_expired_credential_is_invalid(self) -> None:
        # Cria credencial já expirada ignorando a validação de construção
        cred = AgentCredential.model_construct(
            token="test-token",
            issued_at=datetime.now(timezone.utc) - timedelta(hours=2),
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
            revoked=False,
        )
        assert not cred.is_valid()

    def test_revoked_credential_is_invalid(self) -> None:
        cred = AgentCredential(
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        cred.revoke("test")
        assert not cred.is_valid()
        assert cred.revoked_reason == "test"

    def test_invalid_expiry_raises(self) -> None:
        with pytest.raises(ValueError):
            AgentCredential(
                expires_at=datetime.now(timezone.utc) - timedelta(hours=2)
            )


# ── AgentIdentity ──────────────────────────────────────────────────────────

class TestAgentIdentity:
    def test_has_scope(self) -> None:
        identity = make_identity(scopes=[AgentScope.READ_FILES])
        assert identity.has_scope(AgentScope.READ_FILES)
        assert not identity.has_scope(AgentScope.DELETE_FILES)

    def test_issue_credential(self) -> None:
        identity = make_identity()
        cred = identity.issue_credential(ttl_seconds=10)
        assert identity.is_authenticated()
        assert cred.is_valid()

    def test_revoke_credential(self) -> None:
        identity = make_identity()
        identity.issue_credential()
        identity.revoke_credential("test revocation")
        assert not identity.is_authenticated()

    def test_no_credential_not_authenticated(self) -> None:
        identity = make_identity()
        assert not identity.is_authenticated()


# ── DelegationChain ────────────────────────────────────────────────────────

class TestDelegationChain:
    def test_human_delegation(self) -> None:
        chain = DelegationChain()
        agent = make_identity(scopes=[AgentScope.READ_FILES])
        chain.add_link("admin@example.com", agent, [AgentScope.READ_FILES])
        assert AgentScope.READ_FILES in chain.get_effective_scopes(agent.id)

    def test_agent_cannot_delegate_scope_it_lacks(self) -> None:
        chain = DelegationChain()
        parent = make_identity("parent", [AgentScope.READ_FILES])
        child = make_identity("child")
        with pytest.raises(PermissionError, match="não possui"):
            chain.add_link(parent, child, [AgentScope.DELETE_FILES])

    def test_agent_can_delegate_own_scopes(self) -> None:
        chain = DelegationChain()
        parent = make_identity("parent", [AgentScope.READ_FILES, AgentScope.READ_DATABASE])
        child = make_identity("child")
        chain.add_link(parent, child, [AgentScope.READ_FILES])
        scopes = chain.get_effective_scopes(child.id)
        assert AgentScope.READ_FILES in scopes
        assert AgentScope.READ_DATABASE not in scopes

    def test_render_chain(self) -> None:
        chain = DelegationChain()
        agent = make_identity(scopes=[AgentScope.READ_FILES])
        chain.add_link("admin@example.com", agent, [AgentScope.READ_FILES])
        rendered = chain.render()
        assert "admin@example.com" in rendered
        assert agent.name in rendered


# ── IdentityManager ────────────────────────────────────────────────────────

class TestIdentityManager:
    def test_register_issues_credential(self) -> None:
        manager = IdentityManager()
        identity = make_identity()
        manager.register(identity)
        assert identity.is_authenticated()

    def test_duplicate_registration_raises(self) -> None:
        manager = IdentityManager()
        identity = make_identity()
        manager.register(identity)
        with pytest.raises(ValueError, match="já registrado"):
            manager.register(identity)

    def test_revoke_via_manager(self) -> None:
        manager = IdentityManager()
        identity = make_identity()
        manager.register(identity)
        manager.revoke(identity.id, "test")
        assert not identity.is_authenticated()

    def test_validate_credential(self) -> None:
        manager = IdentityManager()
        identity = make_identity()
        manager.register(identity)
        token = identity.credential.token
        assert manager.validate_credential(identity.id, token)
        assert not manager.validate_credential(identity.id, "wrong-token")

    def test_grant_and_revoke_scope(self) -> None:
        manager = IdentityManager()
        identity = make_identity()
        manager.register(identity)
        manager.grant_scope(identity.id, AgentScope.READ_FILES)
        assert identity.has_scope(AgentScope.READ_FILES)
        manager.revoke_scope(identity.id, AgentScope.READ_FILES)
        assert not identity.has_scope(AgentScope.READ_FILES)
