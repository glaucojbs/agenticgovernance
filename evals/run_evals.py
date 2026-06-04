"""
Eval Gate — suíte de avaliação pré-deploy.

Executa todos os cenários adversariais e falha (exit code 1) se qualquer
barreira de governança não segurar. Usado como portão no CI antes de
promover um agente para produção.

Execute: python evals/run_evals.py
       : make eval
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from evals.scenarios.adversarial import ALL_SCENARIOS, EvalResult


def run_all_evals() -> tuple[list[EvalResult], list[EvalResult]]:
    passed: list[EvalResult] = []
    failed: list[EvalResult] = []

    width = 70
    print("=" * width)
    print("  EVAL GATE — Suíte Adversarial de Governança")
    print(f"  {len(ALL_SCENARIOS)} cenários a avaliar")
    print("=" * width)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        for scenario_fn in ALL_SCENARIOS:
            try:
                result = scenario_fn(tmp_path)
            except Exception as exc:
                result = EvalResult(
                    scenario_id=scenario_fn.__name__,
                    description=scenario_fn.__doc__ or "",
                    passed=False,
                    details=f"Exceção não tratada: {exc}",
                    barrier="unknown",
                )

            icon = "✓" if result.passed else "✗"
            status = "PASSOU" if result.passed else "FALHOU"
            print(f"\n  [{icon}] {result.scenario_id} — {status}")
            print(f"       {result.description}")
            print(f"       Barreira : {result.barrier}")
            if not result.passed:
                print(f"       DETALHE  : {result.details}")

            (passed if result.passed else failed).append(result)

    print("\n" + "=" * width)
    print(f"  RESULTADO: {len(passed)}/{len(ALL_SCENARIOS)} cenários passaram")

    if failed:
        print(f"\n  ✗ FALHAS ({len(failed)}):")
        for r in failed:
            print(f"    - [{r.scenario_id}] {r.description}")
            print(f"      Detalhe: {r.details}")
        print()
        print("  ⚠️  EVAL GATE FALHOU — deploy bloqueado")
        print("     Corrija as barreiras listadas antes de promover para produção.")
    else:
        print()
        print("  ✓ EVAL GATE PASSOU — todas as barreiras seguraram")
        print("    O sistema está pronto para promoção.")
    print("=" * width + "\n")

    return passed, failed


if __name__ == "__main__":
    _, failed = run_all_evals()
    sys.exit(1 if failed else 0)
