"""Testes para o circuit breaker."""

import pytest

from governance.circuit_breaker.breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    CircuitOpenError,
    CircuitState,
)


def failing_fn(**kw):
    raise RuntimeError("tool failed")


def ok_fn(**kw):
    return "ok"


class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        cb = CircuitBreaker("tool-a", failure_threshold=3)
        assert cb.state == CircuitState.CLOSED

    def test_opens_after_threshold(self) -> None:
        cb = CircuitBreaker("tool-a", failure_threshold=3, timeout_seconds=999)
        for _ in range(3):
            with pytest.raises(RuntimeError):
                cb.call(failing_fn)
        assert cb.state == CircuitState.OPEN

    def test_open_raises_circuit_open_error(self) -> None:
        cb = CircuitBreaker("tool-a", failure_threshold=2, timeout_seconds=999)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(failing_fn)
        with pytest.raises(CircuitOpenError):
            cb.call(ok_fn)

    def test_success_resets_failure_count(self) -> None:
        cb = CircuitBreaker("tool-a", failure_threshold=3)
        with pytest.raises(RuntimeError):
            cb.call(failing_fn)
        cb.call(ok_fn)  # sucesso reseta
        assert cb._failure_count == 0

    def test_manual_reset(self) -> None:
        cb = CircuitBreaker("tool-a", failure_threshold=2, timeout_seconds=999)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(failing_fn)
        assert cb.state == CircuitState.OPEN
        cb.reset()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_on_timeout(self) -> None:
        cb = CircuitBreaker("tool-a", failure_threshold=2, timeout_seconds=0.0)
        for _ in range(2):
            with pytest.raises(RuntimeError):
                cb.call(failing_fn)
        # Com timeout=0, o próximo acesso ao state já vai para HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN

    def test_registry_creates_breakers(self) -> None:
        reg = CircuitBreakerRegistry(default_failure_threshold=5)
        cb = reg.get_or_create("my-tool")
        assert cb.tool_name == "my-tool"
        # Mesma instância ao chamar novamente
        assert reg.get_or_create("my-tool") is cb

    def test_status(self) -> None:
        cb = CircuitBreaker("tool-x", failure_threshold=3)
        status = cb.status()
        assert status["tool"] == "tool-x"
        assert status["state"] == "closed"
