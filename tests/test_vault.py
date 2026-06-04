"""Testes para o SecretStore simulado."""


import pytest

from governance.vault.store import (
    SecretAccessDeniedError,
    SecretNotFoundError,
    SecretPolicy,
    SecretStore,
)


@pytest.fixture()
def store() -> SecretStore:
    s = SecretStore()
    s.add_policy(SecretPolicy(
        path_prefix="secrets/",
        allowed_agent_ids=["agent-a", "agent-b"],
    ))
    return s


class TestSecretStore:
    def test_write_and_read(self, store: SecretStore) -> None:
        store.write("secrets/db-password", "s3cr3t", written_by="operator")
        lease = store.read("secrets/db-password", agent_id="agent-a")
        assert lease.value == "s3cr3t"
        assert lease.version == 1

    def test_versioning(self, store: SecretStore) -> None:
        store.write("secrets/api-key", "v1")
        store.write("secrets/api-key", "v2")
        lease = store.read("secrets/api-key", agent_id="agent-a")
        assert lease.version == 2
        assert lease.value == "v2"
        # Lê versão anterior
        old = store.read("secrets/api-key", agent_id="agent-a", version=1)
        assert old.value == "v1"

    def test_access_denied(self, store: SecretStore) -> None:
        store.write("secrets/db-password", "s3cr3t")
        with pytest.raises(SecretAccessDeniedError):
            store.read("secrets/db-password", agent_id="unauthorized-agent")

    def test_not_found(self, store: SecretStore) -> None:
        with pytest.raises(SecretNotFoundError):
            store.read("secrets/nonexistent", agent_id="agent-a")

    def test_no_policy_denies(self, store: SecretStore) -> None:
        store.write("internal/config", "value")
        with pytest.raises(SecretAccessDeniedError, match="Nenhuma política"):
            store.read("internal/config", agent_id="agent-a")

    def test_lease_has_ttl(self, store: SecretStore) -> None:
        store.write("secrets/token", "tok123")
        lease = store.read("secrets/token", agent_id="agent-a", lease_ttl=10.0)
        assert lease.time_remaining() > 0
        assert not lease.is_expired()

    def test_rotation_triggers_hook(self, store: SecretStore) -> None:
        rotated = []
        store.write("secrets/key", "original")
        store.on_rotation("secrets/key", lambda path, val: rotated.append(val))
        store.rotate("secrets/key", "rotated-value")
        assert "rotated-value" in rotated

    def test_audit_log_records_access(self, store: SecretStore) -> None:
        store.write("secrets/pw", "pw123")
        store.read("secrets/pw", agent_id="agent-a")
        ops = [e.operation for e in store.audit_log]
        assert "write" in ops
        assert "read" in ops
