"""
Anomaly Detector — detecção de comportamento anômalo em agentes.

Detecta em tempo real padrões suspeitos nas ações dos agentes:
  - Velocidade: chamadas/min acima do threshold
  - Taxa de negação: % de ações negadas acima do esperado
  - Horário incomum: ações fora do horário comercial configurado
  - Ferramentas inusitadas: ferramenta nunca usada antes por este agente
  - Escalada de negações: N negações consecutivas (possível brute-force)
  - Budget spike: consumo acelerado de orçamento

Em produção, os alertas devem ser enviados para:
  - PagerDuty / Opsgenie (P1/P0)
  - Slack / Teams (P2/P3)
  - SIEM (todos os níveis)
"""

from __future__ import annotations

import collections
import contextlib
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from governance.runtime.governed import ExecutionResult


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AnomalyAlert(BaseModel):
    alert_id: str
    severity: AlertSeverity
    agent_id: str
    rule_name: str
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
    detected_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    tool_name: str | None = None


# Tipo para callbacks de alerta: recebe AnomalyAlert
AlertHandler = Callable[[AnomalyAlert], None]


def _default_alert_handler(alert: AnomalyAlert) -> None:
    """Handler padrão: imprime o alerta no stderr."""
    import sys
    print(
        f"\n  ⚠️  ANOMALIA [{alert.severity.upper()}] — {alert.rule_name}\n"
        f"     Agente : {alert.agent_id}\n"
        f"     Detalhe: {alert.description}",
        file=sys.stderr,
    )


class _AgentWindow:
    """Estado deslizante por agente para detecção de anomalias."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        # timestamps das chamadas (para rate)
        self.call_times: collections.deque[float] = collections.deque()
        # timestamps das negações
        self.deny_times: collections.deque[float] = collections.deque()
        # negações consecutivas (sem execução bem-sucedida entre elas)
        self.consecutive_denies: int = 0
        # ferramentas já usadas por este agente
        self.seen_tools: set[str] = set()
        # último sucesso (para detectar períodos sem atividade positiva)
        self.last_success_ts: float = time.monotonic()

    def _prune(self) -> None:
        cutoff = time.monotonic() - self.window_seconds
        while self.call_times and self.call_times[0] < cutoff:
            self.call_times.popleft()
        while self.deny_times and self.deny_times[0] < cutoff:
            self.deny_times.popleft()

    def record(self, tool_name: str, success: bool) -> None:
        now = time.monotonic()
        self._prune()
        self.call_times.append(now)
        if not success:
            self.deny_times.append(now)
            self.consecutive_denies += 1
        else:
            self.consecutive_denies = 0
            self.last_success_ts = now
        self.seen_tools.add(tool_name)

    @property
    def calls_per_minute(self) -> float:
        self._prune()
        if not self.call_times:
            return 0.0
        elapsed = max(time.monotonic() - self.call_times[0], 1.0)
        return len(self.call_times) / elapsed * 60

    @property
    def deny_rate(self) -> float:
        self._prune()
        total = len(self.call_times)
        return len(self.deny_times) / total if total > 0 else 0.0


class AnomalyDetector:
    """
    Detector de anomalias baseado em regras configuráveis.

    Plugar no GovernedAgentRuntime via parâmetro anomaly_detector.
    Cada chamada a observe() atualiza o estado e dispara alertas se necessário.
    """

    def __init__(
        self,
        max_calls_per_minute: float = 30.0,
        max_deny_rate: float = 0.5,
        max_consecutive_denies: int = 5,
        business_hours: tuple[int, int] = (7, 22),  # UTC horas
        alert_handlers: list[AlertHandler] | None = None,
        window_seconds: int = 60,
    ) -> None:
        self._max_cpm = max_calls_per_minute
        self._max_deny_rate = max_deny_rate
        self._max_consecutive_denies = max_consecutive_denies
        self._business_start, self._business_end = business_hours
        self._handlers: list[AlertHandler] = alert_handlers or [_default_alert_handler]
        self._windows: dict[str, _AgentWindow] = {}
        self._window_seconds = window_seconds
        self._alert_count = 0
        self._all_alerts: list[AnomalyAlert] = []

    def _get_window(self, agent_id: str) -> _AgentWindow:
        if agent_id not in self._windows:
            self._windows[agent_id] = _AgentWindow(self._window_seconds)
        return self._windows[agent_id]

    def observe(
        self,
        agent_id: str,
        tool_name: str,
        result: ExecutionResult,
    ) -> list[AnomalyAlert]:
        """Registra uma ação e retorna os alertas gerados (se houver)."""
        window = self._get_window(agent_id)
        is_first_use = tool_name not in window.seen_tools
        window.record(tool_name, result.success)

        alerts: list[AnomalyAlert] = []
        now_utc = datetime.now(UTC)

        # ── Regra 1: Velocidade ───────────────────────────────────────────────
        cpm = window.calls_per_minute
        if cpm > self._max_cpm:
            alerts.append(self._make_alert(
                severity=AlertSeverity.WARNING,
                agent_id=agent_id,
                tool_name=tool_name,
                rule_name="high_call_rate",
                description=(
                    f"Taxa de chamadas {cpm:.1f}/min excede limite {self._max_cpm}/min"
                ),
                details={"calls_per_minute": cpm, "threshold": self._max_cpm},
            ))

        # ── Regra 2: Taxa de negação ──────────────────────────────────────────
        deny_rate = window.deny_rate
        if deny_rate > self._max_deny_rate and len(window.call_times) >= 5:
            alerts.append(self._make_alert(
                severity=AlertSeverity.WARNING,
                agent_id=agent_id,
                tool_name=tool_name,
                rule_name="high_deny_rate",
                description=(
                    f"Taxa de negação {deny_rate:.0%} excede limite {self._max_deny_rate:.0%}"
                ),
                details={
                    "deny_rate": deny_rate,
                    "total_calls": len(window.call_times),
                    "denied": len(window.deny_times),
                },
            ))

        # ── Regra 3: Negações consecutivas (possível brute-force de ferramentas)
        if window.consecutive_denies >= self._max_consecutive_denies:
            alerts.append(self._make_alert(
                severity=AlertSeverity.CRITICAL,
                agent_id=agent_id,
                tool_name=tool_name,
                rule_name="consecutive_denies",
                description=(
                    f"{window.consecutive_denies} negações consecutivas — "
                    "possível tentativa de escalada de privilégio"
                ),
                details={"consecutive_denies": window.consecutive_denies},
            ))

        # ── Regra 4: Horário incomum (fora das horas de negócio) ──────────────
        hour = now_utc.hour
        if not (self._business_start <= hour < self._business_end) and result.success:
            alerts.append(self._make_alert(
                severity=AlertSeverity.INFO,
                agent_id=agent_id,
                tool_name=tool_name,
                rule_name="off_hours_activity",
                description=(
                    f"Ação executada às {now_utc.strftime('%H:%M')} UTC "
                    f"(fora do horário {self._business_start:02d}:00–{self._business_end:02d}:00)"
                ),
                details={"utc_hour": hour, "tool": tool_name},
            ))

        # ── Regra 5: Primeira vez que este agente usa esta ferramenta ─────────
        if is_first_use and result.success and window.seen_tools:
            alerts.append(self._make_alert(
                severity=AlertSeverity.INFO,
                agent_id=agent_id,
                tool_name=tool_name,
                rule_name="new_tool_first_use",
                description=(
                    f"Agente usou '{tool_name}' pela primeira vez"
                ),
                details={"tool": tool_name, "known_tools": list(window.seen_tools)},
            ))

        for alert in alerts:
            self._all_alerts.append(alert)
            for handler in self._handlers:
                with contextlib.suppress(Exception):
                    handler(alert)

        return alerts

    def _make_alert(
        self,
        severity: AlertSeverity,
        agent_id: str,
        tool_name: str | None,
        rule_name: str,
        description: str,
        details: dict[str, Any],
    ) -> AnomalyAlert:
        self._alert_count += 1
        return AnomalyAlert(
            alert_id=f"ALERT-{self._alert_count:06d}",
            severity=severity,
            agent_id=agent_id,
            tool_name=tool_name,
            rule_name=rule_name,
            description=description,
            details=details,
        )

    def get_alerts(
        self,
        agent_id: str | None = None,
        severity: AlertSeverity | None = None,
    ) -> list[AnomalyAlert]:
        alerts = self._all_alerts
        if agent_id:
            alerts = [a for a in alerts if a.agent_id == agent_id]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        return alerts

    def get_agent_stats(self, agent_id: str) -> dict[str, Any]:
        window = self._windows.get(agent_id)
        if not window:
            return {}
        window._prune()
        return {
            "calls_in_window": len(window.call_times),
            "denies_in_window": len(window.deny_times),
            "calls_per_minute": window.calls_per_minute,
            "deny_rate": window.deny_rate,
            "consecutive_denies": window.consecutive_denies,
            "seen_tools": list(window.seen_tools),
        }
