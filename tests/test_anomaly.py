"""Testes para o detector de anomalias."""



from governance.anomaly.detector import AlertSeverity, AnomalyDetector
from governance.runtime.governed import ExecutionResult


def _ok(tool: str = "read_files", agent: str = "a1") -> tuple[str, str, ExecutionResult]:
    return agent, tool, ExecutionResult(success=True, tool_name=tool, agent_id=agent)


def _denied(tool: str = "delete_files", agent: str = "a1") -> tuple[str, str, ExecutionResult]:
    return agent, tool, ExecutionResult(
        success=False, tool_name=tool, agent_id=agent, error="denied"
    )


class TestAnomalyDetector:
    def test_no_alerts_on_normal_activity(self) -> None:
        d = AnomalyDetector(max_calls_per_minute=100, alert_handlers=[])
        agent, tool, result = _ok()
        alerts = d.observe(agent, tool, result)
        # Apenas o alerta INFO de primeira vez
        assert all(a.severity == AlertSeverity.INFO for a in alerts)

    def test_high_rate_triggers_warning(self) -> None:
        d = AnomalyDetector(max_calls_per_minute=2, alert_handlers=[])
        agent = "a1"
        tool = "read_files"
        r = ExecutionResult(success=True, tool_name=tool, agent_id=agent)
        for _ in range(5):
            d.observe(agent, tool, r)
        alerts = d.get_alerts(severity=AlertSeverity.WARNING)
        rate_alerts = [a for a in alerts if a.rule_name == "high_call_rate"]
        assert len(rate_alerts) > 0

    def test_consecutive_denies_triggers_critical(self) -> None:
        d = AnomalyDetector(max_consecutive_denies=3, alert_handlers=[])
        agent, tool, _ = _denied()
        for _ in range(3):
            d.observe(agent, tool, ExecutionResult(success=False, tool_name=tool, agent_id=agent))
        criticals = d.get_alerts(severity=AlertSeverity.CRITICAL)
        assert any(a.rule_name == "consecutive_denies" for a in criticals)

    def test_consecutive_denies_resets_on_success(self) -> None:
        d = AnomalyDetector(max_consecutive_denies=3, alert_handlers=[])
        agent, tool = "a1", "read_files"
        deny_r = ExecutionResult(success=False, tool_name=tool, agent_id=agent)
        ok_r = ExecutionResult(success=True, tool_name=tool, agent_id=agent)
        d.observe(agent, tool, deny_r)
        d.observe(agent, tool, deny_r)
        d.observe(agent, tool, ok_r)  # reseta
        assert d._windows[agent].consecutive_denies == 0

    def test_high_deny_rate_warning(self) -> None:
        d = AnomalyDetector(max_deny_rate=0.3, alert_handlers=[])
        agent, tool = "a1", "read_files"
        for _ in range(3):
            d.observe(agent, tool, ExecutionResult(success=False, tool_name=tool, agent_id=agent))
        for _ in range(2):
            d.observe(agent, tool, ExecutionResult(success=True, tool_name=tool, agent_id=agent))
        warnings = d.get_alerts(severity=AlertSeverity.WARNING)
        assert any(a.rule_name == "high_deny_rate" for a in warnings)

    def test_alert_handler_called(self) -> None:
        received = []
        d = AnomalyDetector(
            max_consecutive_denies=2,
            alert_handlers=[received.append],
        )
        agent, tool = "a1", "bad_tool"
        for _ in range(2):
            d.observe(agent, tool, ExecutionResult(success=False, tool_name=tool, agent_id=agent))
        assert len(received) > 0

    def test_get_agent_stats(self) -> None:
        d = AnomalyDetector(alert_handlers=[])
        agent, tool, result = _ok()
        d.observe(agent, tool, result)
        stats = d.get_agent_stats(agent)
        assert stats["calls_in_window"] == 1
        assert tool in stats["seen_tools"]

    def test_multiple_agents_independent(self) -> None:
        d = AnomalyDetector(max_consecutive_denies=2, alert_handlers=[])
        for agent in ["a1", "a2"]:
            t = "read_files"
            d.observe(agent, t, ExecutionResult(success=True, tool_name=t, agent_id=agent))
        assert d._windows["a1"].consecutive_denies == 0
        assert d._windows["a2"].consecutive_denies == 0
