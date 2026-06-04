"""
Circuit Breaker — resiliência e contenção de falhas em ferramentas.

Estados:
  CLOSED  → funcionamento normal; falhas são contadas
  OPEN    → ferramenta bloqueada; retorna erro imediatamente (fail-fast)
  HALF_OPEN → período de teste; uma chamada de prova decide se fecha ou abre

Benefícios para governança:
  - Impede que uma ferramenta falhando cascateie para outros agentes
  - Reduz blast radius de falhas de ferramentas externas
  - Auditável: cada transição de estado é registrada
  - Configurável por ferramenta: uma API lenta não afeta leituras de arquivo
"""

from __future__ import annotations

import time
from collections.abc import Callable
from enum import StrEnum
from typing import Any

from pydantic import BaseModel


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerEvent(BaseModel):
    tool_name: str
    from_state: CircuitState
    to_state: CircuitState
    reason: str
    timestamp: float


class CircuitBreaker:
    """
    Circuit breaker por ferramenta.

    Parâmetros:
      failure_threshold  — nº de falhas consecutivas para abrir o circuito
      success_threshold  — nº de sucessos em HALF_OPEN para fechar
      timeout_seconds    — tempo em OPEN antes de ir para HALF_OPEN
      excluded_exceptions — exceções que NÃO contam como falha
    """

    def __init__(
        self,
        tool_name: str,
        failure_threshold: int = 5,
        success_threshold: int = 2,
        timeout_seconds: float = 60.0,
        excluded_exceptions: tuple[type[Exception], ...] = (),
    ) -> None:
        self.tool_name = tool_name
        self._failure_threshold = failure_threshold
        self._success_threshold = success_threshold
        self._timeout = timeout_seconds
        self._excluded = excluded_exceptions

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: float = 0.0
        self._events: list[CircuitBreakerEvent] = []

    @property
    def state(self) -> CircuitState:
        # Auto-transição OPEN → HALF_OPEN se o timeout expirou
        if (
            self._state == CircuitState.OPEN
            and time.monotonic() - self._last_failure_time >= self._timeout
        ):
            self._transition(CircuitState.HALF_OPEN, "timeout expirado — iniciando prova")
        return self._state

    def call(self, fn: Callable[..., Any], **kwargs: Any) -> Any:
        """
        Executa `fn` dentro do circuit breaker.
        Levanta CircuitOpenError se o circuito estiver OPEN.
        """
        state = self.state

        if state == CircuitState.OPEN:
            raise CircuitOpenError(
                f"Circuit breaker OPEN para '{self.tool_name}' — "
                f"aguardando {self._timeout:.0f}s antes de tentar novamente"
            )

        try:
            result = fn(**kwargs)
            self._on_success()
            return result
        except Exception as e:
            if self._excluded and isinstance(e, self._excluded):
                raise
            self._on_failure()
            raise

    def _on_success(self) -> None:
        if self._state == CircuitState.HALF_OPEN:
            self._success_count += 1
            if self._success_count >= self._success_threshold:
                self._failure_count = 0
                self._success_count = 0
                self._transition(
                    CircuitState.CLOSED,
                    f"{self._success_count} sucessos em HALF_OPEN — circuito fechado",
                )
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0  # reseta o contador a cada sucesso

    def _on_failure(self) -> None:
        self._last_failure_time = time.monotonic()
        self._failure_count += 1
        self._success_count = 0

        if self._state == CircuitState.HALF_OPEN:
            self._transition(CircuitState.OPEN, "falha em HALF_OPEN — circuito reaberto")
        elif (
            self._state == CircuitState.CLOSED
            and self._failure_count >= self._failure_threshold
        ):
            self._transition(
                CircuitState.OPEN,
                f"{self._failure_count} falhas consecutivas — circuito aberto",
            )

    def _transition(self, to: CircuitState, reason: str) -> None:
        event = CircuitBreakerEvent(
            tool_name=self.tool_name,
            from_state=self._state,
            to_state=to,
            reason=reason,
            timestamp=time.monotonic(),
        )
        self._events.append(event)
        self._state = to

    def reset(self) -> None:
        """Reseta manualmente o circuito para CLOSED (uso operacional)."""
        self._transition(CircuitState.CLOSED, "reset manual pelo operador")
        self._failure_count = 0
        self._success_count = 0

    @property
    def events(self) -> list[CircuitBreakerEvent]:
        return list(self._events)

    def status(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "state": self.state.value,
            "failure_count": self._failure_count,
            "failure_threshold": self._failure_threshold,
            "timeout_seconds": self._timeout,
            "transitions": len(self._events),
        }


class CircuitOpenError(Exception):
    """Levantada quando o circuit breaker está OPEN."""
    pass


class CircuitBreakerRegistry:
    """Catálogo de circuit breakers por ferramenta."""

    def __init__(
        self,
        default_failure_threshold: int = 5,
        default_timeout_seconds: float = 60.0,
    ) -> None:
        self._defaults = {
            "failure_threshold": default_failure_threshold,
            "timeout_seconds": default_timeout_seconds,
        }
        self._breakers: dict[str, CircuitBreaker] = {}

    def get_or_create(self, tool_name: str) -> CircuitBreaker:
        if tool_name not in self._breakers:
            self._breakers[tool_name] = CircuitBreaker(
                tool_name=tool_name,
                **self._defaults,  # type: ignore[arg-type]
            )
        return self._breakers[tool_name]

    def register(self, breaker: CircuitBreaker) -> None:
        self._breakers[breaker.tool_name] = breaker

    def all_status(self) -> list[dict[str, Any]]:
        return [b.status() for b in self._breakers.values()]

    def reset_all(self) -> None:
        for b in self._breakers.values():
            b.reset()
