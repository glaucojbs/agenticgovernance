"""
Allowlist de servidores MCP (Model Context Protocol).

Agentes modernos descobrem ferramentas via servidores MCP. Um servidor MCP
comprometido ou não confiável pode injetar ferramentas maliciosas ou descrições
envenenadas (tool poisoning). A allowlist garante que só ferramentas vindas de
servidores explicitamente confiáveis sejam executáveis.

OWASP ASI07 — Agentic Supply Chain Vulnerabilities.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class McpServer:
    """Um servidor MCP registrado."""

    server_id: str
    url: str
    description: str = ""
    trusted: bool = True
    public_key_pem: str | None = None  # para verificar manifestos assinados


@dataclass
class McpCheckResult:
    allowed: bool
    reason: str = ""


class McpServerAllowlist:
    """Allowlist de servidores MCP confiáveis e o mapa ferramenta → servidor.

    Uso:
        allow = McpServerAllowlist()
        allow.register(McpServer("internal", "mcp://internal.corp"))
        allow.bind_tool("send_email", "internal")
        allow.check_tool("send_email").allowed  # True
        allow.check_tool("evil_tool", server_id="unknown").allowed  # False
    """

    def __init__(self) -> None:
        self._servers: dict[str, McpServer] = {}
        self._tool_origin: dict[str, str] = {}

    def register(self, server: McpServer) -> None:
        self._servers[server.server_id] = server

    def bind_tool(self, tool_name: str, server_id: str) -> None:
        """Associa uma ferramenta ao servidor MCP que a forneceu."""
        self._tool_origin[tool_name] = server_id

    def get(self, server_id: str) -> McpServer | None:
        return self._servers.get(server_id)

    def is_allowed(self, server_id: str) -> bool:
        server = self._servers.get(server_id)
        return server is not None and server.trusted

    def check_tool(self, tool_name: str, server_id: str | None = None) -> McpCheckResult:
        """Verifica se uma ferramenta pode ser usada pela origem informada/registrada."""
        origin = server_id or self._tool_origin.get(tool_name)
        if origin is None:
            return McpCheckResult(
                allowed=False,
                reason=f"ferramenta '{tool_name}' sem servidor MCP de origem conhecido",
            )
        server = self._servers.get(origin)
        if server is None:
            return McpCheckResult(
                allowed=False,
                reason=f"servidor MCP '{origin}' não está na allowlist",
            )
        if not server.trusted:
            return McpCheckResult(
                allowed=False,
                reason=f"servidor MCP '{origin}' marcado como não confiável",
            )
        return McpCheckResult(allowed=True)

    def list_servers(self) -> list[McpServer]:
        return list(self._servers.values())
