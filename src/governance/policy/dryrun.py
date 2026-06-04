"""
PolicyDryRun — simula mudanças de política sem efeito colateral.

Permite testar "se eu alterar esta política, o que mudaria?" antes de
fazer o deploy da nova versão. Compara as decisões atual vs. proposta
sobre um conjunto de requests de teste.

Uso típico no processo de PR de políticas:
  1. Engenheiro modifica policies/my-agent.yaml
  2. CI roda PolicyDryRun comparando antes × depois
  3. Report mostra quais ações seriam promovidas (DENY→ALLOW) ou rebaixadas
  4. Security engineer aprova ou rejeita o PR
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from governance.policy.engine import ActionRequest, PolicyDecision, PolicyEngine, PolicyResult


@dataclass
class DryRunComparison:
    """Resultado da comparação de uma única ActionRequest."""
    request: ActionRequest
    current: PolicyResult
    proposed: PolicyResult

    @property
    def changed(self) -> bool:
        return self.current.decision != self.proposed.decision

    @property
    def is_promotion(self) -> bool:
        """DENY/REQUIRE_APPROVAL → ALLOW: ação se torna mais permissiva."""
        return (
            self.current.decision != PolicyDecision.ALLOW
            and self.proposed.decision == PolicyDecision.ALLOW
        )

    @property
    def is_restriction(self) -> bool:
        """ALLOW → DENY/REQUIRE_APPROVAL: ação se torna mais restritiva."""
        return (
            self.current.decision == PolicyDecision.ALLOW
            and self.proposed.decision != PolicyDecision.ALLOW
        )

    def summary(self) -> str:
        arrow = "→"
        return (
            f"{self.request.agent_name}/{self.request.tool_name} "
            f"[{self.current.decision.value}] {arrow} [{self.proposed.decision.value}]"
        )


@dataclass
class DryRunReport:
    """Relatório completo de um dry-run de política."""
    total: int = 0
    changed: list[DryRunComparison] = field(default_factory=list)
    unchanged: list[DryRunComparison] = field(default_factory=list)
    promotions: list[DryRunComparison] = field(default_factory=list)
    restrictions: list[DryRunComparison] = field(default_factory=list)

    def add(self, comp: DryRunComparison) -> None:
        self.total += 1
        if comp.changed:
            self.changed.append(comp)
            if comp.is_promotion:
                self.promotions.append(comp)
            elif comp.is_restriction:
                self.restrictions.append(comp)
        else:
            self.unchanged.append(comp)

    def render(self) -> str:
        lines = [
            "═" * 60,
            "  POLICY DRY-RUN REPORT",
            "═" * 60,
            f"  Total de requests testados: {self.total}",
            f"  Sem mudança               : {len(self.unchanged)}",
            f"  Com mudança               : {len(self.changed)}",
            f"    ↑ Promoções (→ ALLOW)   : {len(self.promotions)}",
            f"    ↓ Restrições (ALLOW→)   : {len(self.restrictions)}",
        ]
        if self.promotions:
            lines.append("\n  ↑ PROMOÇÕES (mais permissivo):")
            for c in self.promotions:
                lines.append(f"    + {c.summary()}")
        if self.restrictions:
            lines.append("\n  ↓ RESTRIÇÕES (mais restritivo):")
            for c in self.restrictions:
                lines.append(f"    - {c.summary()}")
        if self.changed and not self.promotions and not self.restrictions:
            lines.append("\n  ~ OUTRAS MUDANÇAS:")
            for c in self.changed:
                lines.append(f"    ~ {c.summary()}")
        lines.append("═" * 60)
        return "\n".join(lines)


class PolicyDryRun:
    """
    Compara decisões de dois engines sobre um conjunto de ActionRequests.

    Uso:
        dry_run = PolicyDryRun(
            current=PolicyEngine(current_policies_dir),
            proposed=PolicyEngine(proposed_policies_dir),
        )
        report = dry_run.compare(test_requests)
        print(report.render())
    """

    def __init__(
        self,
        current: PolicyEngine,
        proposed: PolicyEngine,
    ) -> None:
        self._current = current
        self._proposed = proposed

    def compare(self, requests: list[ActionRequest]) -> DryRunReport:
        report = DryRunReport()
        for req in requests:
            current_result = self._current.evaluate(req)
            proposed_result = self._proposed.evaluate(req)
            comp = DryRunComparison(
                request=req,
                current=current_result,
                proposed=proposed_result,
            )
            report.add(comp)
        return report

    @classmethod
    def from_dirs(
        cls,
        current_dir: str | Path,
        proposed_dir: str | Path,
    ) -> PolicyDryRun:
        return cls(
            current=PolicyEngine(current_dir),
            proposed=PolicyEngine(proposed_dir),
        )
