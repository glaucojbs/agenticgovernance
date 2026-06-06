"""
Comunicação inter-agente segura (Agent-to-Agent).

Cobre OWASP ASI04 — Insecure Inter-Agent Communication.

Mensagens entre agentes são assinadas (Ed25519), carregam um token de
capacidade com escopo e validade, e um nonce contra replay. O receptor só
aceita mensagens de remetentes registrados, com assinatura válida, não
expiradas, sem replay e com o escopo exigido.
"""

from governance.a2a.channel import (
    AgentMessage,
    CapabilityToken,
    ReceiveResult,
    SignedAgentChannel,
)

__all__ = [
    "AgentMessage",
    "CapabilityToken",
    "ReceiveResult",
    "SignedAgentChannel",
]
