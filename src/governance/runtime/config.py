"""
GovernanceConfig — configuração opcional do GovernedAgentRuntime.

Agrupa todas as capacidades opcionais num único objeto, mantendo o
construtor do runtime limpo e extensível sem quebrar retro-compatibilidade.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from governance.anomaly.detector import AnomalyDetector
    from governance.circuit_breaker.breaker import CircuitBreakerRegistry
    from governance.masking.masker import PIIMasker
    from governance.telemetry.otel import GovernanceTelemetry


@dataclass
class GovernanceConfig:
    """
    Configuração opcional injetada no GovernedAgentRuntime.

    Todos os campos são None por padrão — o runtime funciona sem eles
    (retrocompatível com todos os testes e exemplos existentes).
    """

    timeout_seconds: int = 30
    telemetry: GovernanceTelemetry | None = None
    anomaly_detector: AnomalyDetector | None = None
    pii_masker: PIIMasker | None = None
    circuit_breakers: CircuitBreakerRegistry | None = None

    @classmethod
    def default(cls) -> GovernanceConfig:
        return cls()
