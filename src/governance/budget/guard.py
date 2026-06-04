"""
Budget Guard — contenção de orçamento por agente.

Controla tetos de custo (USD simulado), tokens, número de chamadas e
taxa de chamadas por minuto. Ao estourar qualquer limite, bloqueia a
próxima ação e registra o evento de auditoria.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class BudgetConfig(BaseModel):
    """Configuração dos tetos de orçamento para um agente."""

    max_cost_usd: float = 10.0
    max_tokens: int = 100_000
    max_calls: int = 1_000
    max_calls_per_minute: int = 60

    # Custo e tokens por chamada padrão (simulado)
    default_cost_per_call_usd: float = 0.001
    default_tokens_per_call: int = 500


class BudgetStatus(BaseModel):
    """Estado corrente do orçamento de um agente."""

    agent_id: str
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    total_calls: int = 0
    last_reset: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    blocked: bool = False
    block_reason: Optional[str] = None


class BudgetExceededError(Exception):
    """Levantada quando uma ação violaria um limite de orçamento."""

    def __init__(self, agent_id: str, reason: str) -> None:
        self.agent_id = agent_id
        self.reason = reason
        super().__init__(f"Orçamento excedido para '{agent_id}': {reason}")


class BudgetGuard:
    """
    Guarda de orçamento por agente.

    Mantém contadores em memória; em produção, persistir em Redis ou banco.
    """

    def __init__(self, config: Optional[BudgetConfig] = None) -> None:
        self._config = config or BudgetConfig()
        self._statuses: dict[str, BudgetStatus] = {}
        # Janela deslizante de timestamps das chamadas (para rate limiting)
        self._call_timestamps: dict[str, deque[datetime]] = {}

    def _get_or_create(self, agent_id: str) -> BudgetStatus:
        if agent_id not in self._statuses:
            self._statuses[agent_id] = BudgetStatus(agent_id=agent_id)
            self._call_timestamps[agent_id] = deque()
        return self._statuses[agent_id]

    def check_and_consume(
        self,
        agent_id: str,
        cost_usd: Optional[float] = None,
        tokens: Optional[int] = None,
    ) -> BudgetStatus:
        """
        Verifica se a próxima ação cabe no orçamento e registra o consumo.

        Levanta BudgetExceededError se qualquer limite seria ultrapassado.
        """
        status = self._get_or_create(agent_id)
        cfg = self._config

        call_cost = cost_usd if cost_usd is not None else cfg.default_cost_per_call_usd
        call_tokens = tokens if tokens is not None else cfg.default_tokens_per_call
        now = datetime.now(timezone.utc)

        # Verifica custo
        if status.total_cost_usd + call_cost > cfg.max_cost_usd:
            reason = (
                f"custo USD acumulado {status.total_cost_usd:.4f} + {call_cost:.4f} "
                f"> limite {cfg.max_cost_usd:.2f}"
            )
            status.blocked = True
            status.block_reason = reason
            raise BudgetExceededError(agent_id, reason)

        # Verifica tokens
        if status.total_tokens + call_tokens > cfg.max_tokens:
            reason = (
                f"tokens acumulados {status.total_tokens} + {call_tokens} "
                f"> limite {cfg.max_tokens}"
            )
            status.blocked = True
            status.block_reason = reason
            raise BudgetExceededError(agent_id, reason)

        # Verifica número de chamadas
        if status.total_calls + 1 > cfg.max_calls:
            reason = f"número de chamadas {status.total_calls} atingiu limite {cfg.max_calls}"
            status.blocked = True
            status.block_reason = reason
            raise BudgetExceededError(agent_id, reason)

        # Verifica rate limit (janela de 60 segundos)
        timestamps = self._call_timestamps[agent_id]
        cutoff = now.timestamp() - 60.0
        while timestamps and timestamps[0].timestamp() < cutoff:
            timestamps.popleft()

        if len(timestamps) >= cfg.max_calls_per_minute:
            reason = (
                f"taxa de {len(timestamps)} chamadas/min excede limite "
                f"{cfg.max_calls_per_minute}/min"
            )
            status.blocked = True
            status.block_reason = reason
            raise BudgetExceededError(agent_id, reason)

        # Registra consumo
        status.total_cost_usd += call_cost
        status.total_tokens += call_tokens
        status.total_calls += 1
        timestamps.append(now)
        status.blocked = False
        status.block_reason = None
        return status

    def get_status(self, agent_id: str) -> Optional[BudgetStatus]:
        return self._statuses.get(agent_id)

    def reset(self, agent_id: str) -> None:
        """Reseta os contadores de um agente (ex.: início de novo período)."""
        self._statuses[agent_id] = BudgetStatus(agent_id=agent_id)
        self._call_timestamps[agent_id] = deque()

    def set_config(self, config: BudgetConfig) -> None:
        self._config = config
