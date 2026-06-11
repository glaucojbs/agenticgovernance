"""
Model / System Card para agentes governados.

A documentação técnica de modelos (model card) é obrigação explícita do
EU AI Act GPAI (Art. 53, em vigor desde ago/2025) e prática recomendada do
NIST GenAI Profile (AI 600-1). Para sistemas agênticos, estendemos o cartão
clássico com a postura de governança: escopos, controles ativos e mapeamento
das categorias de risco do NIST GenAI.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

# As 12 categorias de risco do NIST AI 600-1 (Generative AI Profile).
NIST_GENAI_RISK_CATEGORIES = (
    "CBRN Information or Capabilities",
    "Confabulation",
    "Dangerous, Violent, or Hateful Content",
    "Data Privacy",
    "Environmental Impacts",
    "Harmful Bias or Homogenization",
    "Human-AI Configuration",
    "Information Integrity",
    "Information Security",
    "Intellectual Property",
    "Obscene, Degrading, and/or Abusive Content",
    "Value Chain and Component Integration",
)


@dataclass
class ModelCard:
    """Cartão de modelo/sistema agêntico."""

    name: str
    version: str
    owner: str
    generated_at: str
    intended_use: str
    out_of_scope_uses: list[str] = field(default_factory=list)
    granted_scopes: list[str] = field(default_factory=list)
    governance_controls: list[str] = field(default_factory=list)
    risk_categories_addressed: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    contact: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    def render(self) -> str:
        lines = [
            f"# Model Card — {self.name} v{self.version}",
            "",
            f"- **Responsável:** {self.owner}",
            f"- **Gerado em:** {self.generated_at[:19]}",
            f"- **Uso pretendido:** {self.intended_use}",
            "",
            "## Escopos concedidos",
            *(f"- {s}" for s in self.granted_scopes or ["(nenhum)"]),
            "",
            "## Controles de governança ativos",
            *(f"- {c}" for c in self.governance_controls),
            "",
            "## Categorias de risco NIST GenAI endereçadas",
            *(f"- {r}" for r in self.risk_categories_addressed),
            "",
            "## Usos fora de escopo",
            *(f"- {u}" for u in self.out_of_scope_uses),
            "",
            "## Limitações",
            *(f"- {limitation}" for limitation in self.limitations),
        ]
        return "\n".join(lines)


def generate_model_card(
    name: str,
    version: str,
    owner: str,
    intended_use: str,
    granted_scopes: list[str] | None = None,
    governance_controls: list[str] | None = None,
    risk_categories_addressed: list[str] | None = None,
    out_of_scope_uses: list[str] | None = None,
    limitations: list[str] | None = None,
    contact: str = "",
) -> ModelCard:
    """Monta um ModelCard com defaults sensatos para um agente governado."""
    return ModelCard(
        name=name,
        version=version,
        owner=owner,
        generated_at=datetime.now(UTC).isoformat(),
        intended_use=intended_use,
        out_of_scope_uses=out_of_scope_uses
        or ["operação sem supervisão em produção sem aprovação", "ações destrutivas/irreversíveis"],
        granted_scopes=granted_scopes or [],
        governance_controls=governance_controls
        or [
            "política como código (default-deny)",
            "auditoria hash-chain + Ed25519",
            "guardrails de conteúdo (prompt injection / DLP)",
            "integridade de ferramentas (anti tool-poisoning)",
            "memória governada (anti poisoning)",
            "comunicação A2A assinada",
            "kill switch + aprovação humana",
        ],
        risk_categories_addressed=risk_categories_addressed
        or [
            "Information Integrity",
            "Data Privacy",
            "Information Security",
            "Human-AI Configuration",
        ],
        limitations=limitations
        or [
            "guardrails determinísticos: classificador LLM é opcional e plugável",
            "armazenamento de memória/segredos em processo (produção: Vault/KMS)",
        ],
        contact=contact or owner,
    )
