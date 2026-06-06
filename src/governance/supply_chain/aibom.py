"""
AI-BOM — AI Bill of Materials.

Inventário verificável dos componentes do sistema agêntico: ferramentas (com
hash/assinatura), modelos e bibliotecas. É o análogo do SBOM para IA, exigido
por frameworks de governança modernos (EU AI Act GPAI, NIST GenAI Profile) para
rastrear proveniência e responder a incidentes de supply chain.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from governance.registry.catalog import ToolRegistry
    from governance.supply_chain.tool_integrity import ToolIntegrityRegistry


@dataclass
class AIBomComponent:
    """Um componente do inventário."""

    type: str  # "tool" | "model" | "library"
    name: str
    version: str = ""
    digest: str | None = None
    origin: str | None = None  # servidor MCP, registro de modelos, etc.
    risk_level: str | None = None
    signed: bool = False


@dataclass
class AIBom:
    """Inventário completo (AI Bill of Materials)."""

    generated_at: str
    components: list[AIBomComponent] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.components:
            counts[c.type] = counts.get(c.type, 0) + 1
        return counts

    def to_json(self) -> str:
        return json.dumps(
            {
                "generated_at": self.generated_at,
                "summary": self.summary(),
                "components": [asdict(c) for c in self.components],
            },
            indent=2,
            ensure_ascii=False,
        )

    def render(self) -> str:
        lines = [
            "╔" + "═" * 72 + "╗",
            "║  AI-BOM — AI Bill of Materials" + " " * 41 + "║",
            "╠" + "═" * 72 + "╣",
            f"║  Gerado em: {self.generated_at[:19]:<59}║",
            f"║  Componentes: {str(self.summary()):<57}║",
            "╠" + "═" * 72 + "╣",
        ]
        for c in self.components:
            sig = "🔏" if c.signed else "  "
            digest = (c.digest or "")[:12]
            lines.append(
                f"║ {sig}[{c.type:<7}] {c.name[:24]:<24} {c.version[:8]:<8} {digest:<12} {(c.origin or '-')[:8]:<8}║"
            )
        lines.append("╚" + "═" * 72 + "╝")
        return "\n".join(lines)


def generate_aibom(
    tool_registry: ToolRegistry,
    integrity_registry: ToolIntegrityRegistry | None = None,
    models: list[AIBomComponent] | None = None,
    libraries: list[AIBomComponent] | None = None,
) -> AIBom:
    """Gera um AI-BOM a partir do registro de ferramentas (+ modelos/libs informados)."""
    components: list[AIBomComponent] = []

    for definition in tool_registry.list_tools():
        pin = integrity_registry.get_pin(definition.name) if integrity_registry else None
        components.append(
            AIBomComponent(
                type="tool",
                name=definition.name,
                version="",
                digest=pin.digest if pin else None,
                origin=pin.server_id if pin else None,
                risk_level=definition.risk_level.value,
                signed=bool(pin and pin.signature),
            )
        )

    components.extend(models or [])
    components.extend(libraries or [])

    return AIBom(
        generated_at=datetime.now(UTC).isoformat(),
        components=components,
    )
