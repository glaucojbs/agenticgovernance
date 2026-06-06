"""
Integridade de ferramentas — defesa contra tool poisoning.

Cada ferramenta tem uma "impressão digital" (fingerprint) calculada sobre seus
metadados de governança + o código-fonte da implementação. Pinamos a fingerprint
num estado conhecido-bom; antes de cada execução, recomputamos e comparamos.

Qualquer divergência (descrição trocada para enganar o agente, implementação
substituída, escopo elevado silenciosamente) é detectada como violação.

Opcionalmente, a fingerprint é assinada com Ed25519 (`AuditSigner`): assim,
um atacante com acesso ao registro de pins não consegue forjar um novo pin
válido sem a chave privada.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from governance.registry.catalog import ToolDefinition, ToolRegistry
    from governance.signing.signer import AuditSigner


@dataclass
class ToolFingerprint:
    """Impressão digital pinada de uma ferramenta."""

    tool_name: str
    digest: str  # sha256 hex dos metadados + fonte da implementação
    server_id: str | None = None  # origem (servidor MCP), quando aplicável
    signature: str | None = None  # assinatura Ed25519 do digest (base64), opcional
    algorithm: str = "sha256"


@dataclass
class IntegrityResult:
    """Resultado de uma verificação de integridade."""

    ok: bool
    tool_name: str
    reason: str = ""
    expected_digest: str | None = None
    actual_digest: str | None = None


def _impl_source(implementation: Callable[..., Any] | None) -> str:
    """Representação estável do código de uma implementação para hashing."""
    if implementation is None:
        return "<no-impl>"
    try:
        return inspect.getsource(implementation)
    except (OSError, TypeError):
        # Builtins / callables sem fonte: usa qualname + módulo como fallback
        mod = getattr(implementation, "__module__", "?")
        qual = getattr(implementation, "__qualname__", repr(implementation))
        return f"{mod}.{qual}"


def compute_fingerprint(
    definition: ToolDefinition,
    implementation: Callable[..., Any] | None,
) -> str:
    """Calcula o digest sha256 de uma ferramenta (metadados + fonte)."""
    payload = {
        "name": definition.name,
        "description": definition.description,
        "risk_level": definition.risk_level.value,
        "required_scope": definition.required_scope.value,
        "is_destructive": definition.is_destructive,
        "is_reversible": definition.is_reversible,
        "allowed_environments": sorted(e.value for e in definition.allowed_environments),
        "impl_source": _impl_source(implementation),
    }
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


class ToolIntegrityRegistry:
    """Registro de fingerprints pinadas, com verificação de drift.

    Uso:
        integrity = ToolIntegrityRegistry(signer=signer)
        integrity.pin_registry(tool_registry)        # snapshot conhecido-bom
        ...
        result = integrity.verify(tool_registry, "send_email")
        if not result.ok:
            # tool poisoning detectado — bloquear
    """

    def __init__(self, signer: AuditSigner | None = None) -> None:
        self._pins: dict[str, ToolFingerprint] = {}
        self._signer = signer

    def pin(
        self,
        definition: ToolDefinition,
        implementation: Callable[..., Any] | None = None,
        server_id: str | None = None,
    ) -> ToolFingerprint:
        """Pina a fingerprint atual de uma ferramenta como estado confiável."""
        digest = compute_fingerprint(definition, implementation)
        signature = self._signer.sign_message(digest) if self._signer else None
        fp = ToolFingerprint(
            tool_name=definition.name,
            digest=digest,
            server_id=server_id,
            signature=signature,
        )
        self._pins[definition.name] = fp
        return fp

    def pin_registry(self, registry: ToolRegistry, server_id: str | None = None) -> None:
        """Pina todas as ferramentas de um ToolRegistry."""
        for definition in registry.list_tools():
            impl = registry.get_implementation(definition.name)
            self.pin(definition, impl, server_id=server_id)

    def get_pin(self, tool_name: str) -> ToolFingerprint | None:
        return self._pins.get(tool_name)

    def verify(self, registry: ToolRegistry, tool_name: str) -> IntegrityResult:
        """Verifica a integridade de uma ferramenta contra seu pin."""
        definition = registry.get(tool_name)
        if definition is None:
            return IntegrityResult(ok=False, tool_name=tool_name, reason="ferramenta não registrada")
        impl = registry.get_implementation(tool_name)
        return self.verify_definition(definition, impl)

    def verify_definition(
        self,
        definition: ToolDefinition,
        implementation: Callable[..., Any] | None,
    ) -> IntegrityResult:
        pin = self._pins.get(definition.name)
        if pin is None:
            return IntegrityResult(
                ok=False,
                tool_name=definition.name,
                reason="ferramenta não pinada (origem desconhecida)",
            )

        actual = compute_fingerprint(definition, implementation)
        if actual != pin.digest:
            return IntegrityResult(
                ok=False,
                tool_name=definition.name,
                reason="fingerprint divergente — possível tool poisoning",
                expected_digest=pin.digest,
                actual_digest=actual,
            )

        # Verifica assinatura, se houver signer e assinatura pinada
        if self._signer and pin.signature:
            valid = self._signer.verify_message(
                pin.digest, pin.signature, self._signer.public_key_pem()
            )
            if not valid:
                return IntegrityResult(
                    ok=False,
                    tool_name=definition.name,
                    reason="assinatura do pin inválida",
                    expected_digest=pin.digest,
                    actual_digest=actual,
                )

        return IntegrityResult(
            ok=True,
            tool_name=definition.name,
            expected_digest=pin.digest,
            actual_digest=actual,
        )

    def all_pins(self) -> list[ToolFingerprint]:
        return list(self._pins.values())
