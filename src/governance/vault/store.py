"""
SecretStore — cofre de segredos simulado.

Ensina o padrão Vault/KMS sem dependência externa:
  - Segredos com TTL e renovação automática de lease
  - Versionamento: cada escrita cria uma versão; versões antigas podem ser lidas
  - Access policy: quais agent_ids podem ler qual path
  - Auditoria de todos os acessos (quem leu o quê e quando)
  - Rotação automática com notificação

Em produção: substituir por HashiCorp Vault, AWS Secrets Manager ou GCP Secret Manager.
O código do agente não muda — apenas a implementação de SecretStore.
"""

from __future__ import annotations

import contextlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecretVersion:
    value: Any
    version: int
    created_at: float
    expires_at: float | None  # None = sem expiração

    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return time.monotonic() > self.expires_at


@dataclass
class SecretLease:
    """Lease retornado ao agente ao ler um segredo."""

    lease_id: str
    path: str
    version: int
    value: Any
    ttl_seconds: float
    renewable: bool
    expires_at: float

    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at

    def time_remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())


@dataclass
class SecretPolicy:
    """Quais agent_ids têm acesso a qual path (prefixo)."""

    path_prefix: str
    allowed_agent_ids: list[str]
    allow_list: bool = True  # True=allow list, False=deny list
    max_versions: int = 5  # versões preservadas

    def allows(self, agent_id: str) -> bool:
        if self.allow_list:
            return agent_id in self.allowed_agent_ids
        return agent_id not in self.allowed_agent_ids


@dataclass
class SecretAccessEvent:
    agent_id: str
    path: str
    operation: str  # "read" | "write" | "rotate" | "revoke"
    version: int
    lease_id: str
    timestamp: float = field(default_factory=time.monotonic)
    success: bool = True
    error: str | None = None


class SecretAccessDeniedError(Exception):
    pass


class SecretNotFoundError(Exception):
    pass


class SecretStore:
    """
    Cofre de segredos em memória com TTL, versionamento e access policy.

    Mimetiza a API do HashiCorp Vault KV v2.
    """

    def __init__(self) -> None:
        # path → lista de versões (ordenadas por version)
        self._secrets: dict[str, list[SecretVersion]] = {}
        self._policies: list[SecretPolicy] = []
        self._leases: dict[str, SecretLease] = {}
        self._audit_log: list[SecretAccessEvent] = []
        # Callbacks de rotação: path → callable chamado após rotate()
        self._rotation_hooks: dict[str, list[Callable[[str, Any], None]]] = {}

    # ── Política de acesso ────────────────────────────────────────────────────

    def add_policy(self, policy: SecretPolicy) -> None:
        self._policies.append(policy)

    def _check_access(self, agent_id: str, path: str) -> None:
        for policy in self._policies:
            if path.startswith(policy.path_prefix):
                if not policy.allows(agent_id):
                    raise SecretAccessDeniedError(
                        f"Agente '{agent_id}' não tem acesso ao path '{path}'"
                    )
                return
        # Sem política correspondente: nega por padrão
        raise SecretAccessDeniedError(f"Nenhuma política de acesso para '{path}' — acesso negado")

    # ── Operações ────────────────────────────────────────────────────────────

    def write(
        self,
        path: str,
        value: Any,
        ttl_seconds: float | None = None,
        written_by: str = "operator",
    ) -> int:
        """Escreve um segredo. Retorna o número da versão criada."""
        if path not in self._secrets:
            self._secrets[path] = []

        versions = self._secrets[path]
        next_version = (versions[-1].version + 1) if versions else 1
        expires_at = (time.monotonic() + ttl_seconds) if ttl_seconds else None

        versions.append(
            SecretVersion(
                value=value,
                version=next_version,
                created_at=time.monotonic(),
                expires_at=expires_at,
            )
        )

        # Mantém apenas as últimas N versões
        max_v = next(
            (p.max_versions for p in self._policies if path.startswith(p.path_prefix)),
            5,
        )
        if len(versions) > max_v:
            versions[:] = versions[-max_v:]

        self._audit_log.append(
            SecretAccessEvent(
                agent_id=written_by,
                path=path,
                operation="write",
                version=next_version,
                lease_id="",
            )
        )
        return next_version

    def read(
        self,
        path: str,
        agent_id: str,
        version: int | None = None,
        lease_ttl: float = 300.0,
    ) -> SecretLease:
        """Lê um segredo e retorna um lease com TTL."""
        self._check_access(agent_id, path)

        if path not in self._secrets or not self._secrets[path]:
            self._audit_log.append(
                SecretAccessEvent(
                    agent_id=agent_id,
                    path=path,
                    operation="read",
                    version=0,
                    lease_id="",
                    success=False,
                    error="not found",
                )
            )
            raise SecretNotFoundError(f"Segredo '{path}' não encontrado")

        versions = self._secrets[path]
        if version is not None:
            sv = next((v for v in versions if v.version == version), None)
        else:
            sv = versions[-1]

        if sv is None or sv.is_expired():
            raise SecretNotFoundError(f"Versão {version} de '{path}' não encontrada ou expirada")

        lease_id = secrets.token_hex(16)
        lease = SecretLease(
            lease_id=lease_id,
            path=path,
            version=sv.version,
            value=sv.value,
            ttl_seconds=lease_ttl,
            renewable=True,
            expires_at=time.monotonic() + lease_ttl,
        )
        self._leases[lease_id] = lease
        self._audit_log.append(
            SecretAccessEvent(
                agent_id=agent_id,
                path=path,
                operation="read",
                version=sv.version,
                lease_id=lease_id,
            )
        )
        return lease

    def renew_lease(self, lease_id: str, agent_id: str) -> SecretLease:
        lease = self._leases.get(lease_id)
        if not lease:
            raise SecretNotFoundError(f"Lease '{lease_id}' não encontrado")
        if not lease.renewable:
            raise PermissionError(f"Lease '{lease_id}' não é renovável")
        lease.expires_at = time.monotonic() + lease.ttl_seconds
        self._audit_log.append(
            SecretAccessEvent(
                agent_id=agent_id,
                path=lease.path,
                operation="renew",
                version=lease.version,
                lease_id=lease_id,
            )
        )
        return lease

    def revoke_lease(self, lease_id: str) -> None:
        lease = self._leases.pop(lease_id, None)
        if lease:
            self._audit_log.append(
                SecretAccessEvent(
                    agent_id="system",
                    path=lease.path,
                    operation="revoke",
                    version=lease.version,
                    lease_id=lease_id,
                )
            )

    def rotate(self, path: str, new_value: Any, written_by: str = "operator") -> int:
        """Rotaciona um segredo — mantém versão anterior disponível brevemente."""
        version = self.write(path, new_value, written_by=written_by)
        # Chama hooks de rotação (ex.: agente que usa o segredo deve recarregar)
        for hook in self._rotation_hooks.get(path, []):
            with contextlib.suppress(Exception):
                hook(path, new_value)
        self._audit_log.append(
            SecretAccessEvent(
                agent_id=written_by,
                path=path,
                operation="rotate",
                version=version,
                lease_id="",
            )
        )
        return version

    def on_rotation(self, path: str, callback: Callable[[str, Any], None]) -> None:
        """Registra callback chamado quando o segredo é rotacionado."""
        self._rotation_hooks.setdefault(path, []).append(callback)

    @property
    def audit_log(self) -> list[SecretAccessEvent]:
        return list(self._audit_log)

    def list_paths(self, prefix: str = "") -> list[str]:
        return [p for p in self._secrets if p.startswith(prefix)]

    def versions(self, path: str) -> list[int]:
        return [v.version for v in self._secrets.get(path, [])]
