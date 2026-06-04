"""Testes para o budget guard."""

import pytest

from governance.budget.guard import BudgetConfig, BudgetExceededError, BudgetGuard


@pytest.fixture()
def guard() -> BudgetGuard:
    config = BudgetConfig(
        max_cost_usd=0.01,
        max_tokens=1000,
        max_calls=5,
        max_calls_per_minute=100,
        default_cost_per_call_usd=0.002,
        default_tokens_per_call=100,
    )
    return BudgetGuard(config)


class TestBudgetGuard:
    def test_first_call_succeeds(self, guard: BudgetGuard) -> None:
        status = guard.check_and_consume("agent-1")
        assert status.total_calls == 1
        assert not status.blocked

    def test_max_calls_exceeded(self) -> None:
        # Configura custo alto para que apenas o limite de chamadas seja atingido
        config = BudgetConfig(
            max_calls=3,
            max_cost_usd=100.0,
            max_tokens=1_000_000,
            default_cost_per_call_usd=0.0001,
            default_tokens_per_call=1,
        )
        guard = BudgetGuard(config)
        for _ in range(3):
            guard.check_and_consume("agent-1")
        with pytest.raises(BudgetExceededError, match="número de chamadas"):
            guard.check_and_consume("agent-1")

    def test_cost_exceeded(self, guard: BudgetGuard) -> None:
        # max_cost=0.01, default_cost=0.002 → cabe 5 chamadas (5*0.002=0.01)
        for _ in range(5):
            guard.check_and_consume("agent-1")
        with pytest.raises(BudgetExceededError):
            guard.check_and_consume("agent-1")

    def test_token_exceeded(self) -> None:
        config = BudgetConfig(
            max_tokens=150,
            max_cost_usd=100,
            max_calls=100,
            default_tokens_per_call=100,
        )
        guard = BudgetGuard(config)
        guard.check_and_consume("agent-1")
        with pytest.raises(BudgetExceededError, match="tokens"):
            guard.check_and_consume("agent-1")

    def test_different_agents_are_independent(self, guard: BudgetGuard) -> None:
        for _ in range(5):
            guard.check_and_consume("agent-1")
        # agent-2 ainda tem orçamento
        status = guard.check_and_consume("agent-2")
        assert status.total_calls == 1

    def test_reset_clears_budget(self, guard: BudgetGuard) -> None:
        for _ in range(5):
            guard.check_and_consume("agent-1")
        guard.reset("agent-1")
        status = guard.check_and_consume("agent-1")
        assert status.total_calls == 1

    def test_get_status_returns_none_for_unknown(self, guard: BudgetGuard) -> None:
        assert guard.get_status("nonexistent") is None

    def test_budget_exceeded_sets_blocked_flag(self, guard: BudgetGuard) -> None:
        for _ in range(5):
            guard.check_and_consume("agent-1")
        with pytest.raises(BudgetExceededError):
            guard.check_and_consume("agent-1")
        status = guard.get_status("agent-1")
        assert status is not None
        assert status.blocked
