"""Testes para o approval gate e kill switch."""

from pathlib import Path

import pytest

from governance.approval.gate import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
    KillSwitchActiveError,
)


def make_request(request_id: str = "req-001") -> ApprovalRequest:
    return ApprovalRequest(
        request_id=request_id,
        agent_id="agent-1",
        agent_name="Test Agent",
        tool_name="send_email",
        risk_level="high",
        reason="ação de alto risco em produção",
    )


@pytest.fixture()
def tmp_kill_switch(tmp_path: Path) -> Path:
    return tmp_path / ".kill_switch"


class TestApprovalGate:
    def test_auto_approve(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch, auto_approve=True)
        req = make_request()
        result = gate.request_approval(req)
        assert result.decision == ApprovalDecision.GRANTED

    def test_auto_deny(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch, auto_deny=True)
        req = make_request()
        result = gate.request_approval(req)
        assert result.decision == ApprovalDecision.DENIED

    def test_callback_approve(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(
            kill_switch_path=tmp_kill_switch,
            approver_callback=lambda r: (True, "approved by callback"),
        )
        result = gate.request_approval(make_request())
        assert result.decision == ApprovalDecision.GRANTED
        assert result.decision_notes == "approved by callback"

    def test_callback_deny(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(
            kill_switch_path=tmp_kill_switch,
            approver_callback=lambda r: (False, "too risky"),
        )
        result = gate.request_approval(make_request())
        assert result.decision == ApprovalDecision.DENIED

    def test_no_approver_configured_defaults_to_deny(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch)
        result = gate.request_approval(make_request())
        assert result.decision == ApprovalDecision.DENIED

    def test_auto_deny_takes_precedence_over_auto_approve(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(
            kill_switch_path=tmp_kill_switch,
            auto_deny=True,
            auto_approve=True,
        )
        result = gate.request_approval(make_request())
        assert result.decision == ApprovalDecision.DENIED


class TestKillSwitch:
    def test_kill_switch_inactive_by_default(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch)
        assert not gate.is_kill_switch_active()

    def test_activate_kill_switch(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch)
        gate.activate_kill_switch("test activation")
        assert gate.is_kill_switch_active()
        assert tmp_kill_switch.exists()

    def test_deactivate_kill_switch(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch)
        gate.activate_kill_switch()
        gate.deactivate_kill_switch()
        assert not gate.is_kill_switch_active()

    def test_check_kill_switch_raises_when_active(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch)
        gate.activate_kill_switch("emergency stop")
        with pytest.raises(KillSwitchActiveError, match="emergency stop"):
            gate.check_kill_switch()

    def test_check_kill_switch_passes_when_inactive(self, tmp_kill_switch: Path) -> None:
        gate = ApprovalGate(kill_switch_path=tmp_kill_switch)
        gate.check_kill_switch()  # should not raise
