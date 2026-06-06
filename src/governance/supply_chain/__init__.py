"""
Supply-chain de ferramentas — integridade, proveniência e MCP.

Cobre OWASP Top 10 for Agentic Applications:
  - ASI06 Tool Misuse & Exploitation
  - ASI07 Agentic Supply Chain Vulnerabilities (tool poisoning, MCP comprometido)

Componentes:
  - ToolIntegrityRegistry — pina cada ferramenta por hash (e assinatura Ed25519
    opcional) e detecta drift/adulteração antes da execução.
  - McpServerAllowlist    — só permite ferramentas vindas de servidores MCP
    explicitamente confiáveis.
  - AI-BOM                — inventário verificável de ferramentas/modelos.
"""

from governance.supply_chain.aibom import AIBom, AIBomComponent, generate_aibom
from governance.supply_chain.mcp import McpServer, McpServerAllowlist
from governance.supply_chain.tool_integrity import (
    IntegrityResult,
    ToolFingerprint,
    ToolIntegrityRegistry,
)

__all__ = [
    "AIBom",
    "AIBomComponent",
    "IntegrityResult",
    "McpServer",
    "McpServerAllowlist",
    "ToolFingerprint",
    "ToolIntegrityRegistry",
    "generate_aibom",
]
