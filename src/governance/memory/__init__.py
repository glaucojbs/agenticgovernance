"""
Governança de memória do agente — defesa contra memory & context poisoning.

Cobre OWASP ASI09 — Memory & Context Poisoning.

Toda entrada de memória carrega proveniência e um rótulo de confiança. Conteúdo
vindo de ferramentas ou de fontes externas nasce UNTRUSTED; na recuperação, ele
passa pelos guardrails e, se contiver injeção, é colocado em QUARENTENA e não é
devolvido ao agente.
"""

from governance.memory.store import (
    GovernedMemoryStore,
    MemoryEntry,
    MemoryOrigin,
    TrustLabel,
)

__all__ = [
    "GovernedMemoryStore",
    "MemoryEntry",
    "MemoryOrigin",
    "TrustLabel",
]
