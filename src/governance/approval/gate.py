"""
Approval Gate — supervisão humana proporcional ao risco (HITL/HOTL).

Para ações que o motor de política classifica como REQUIRE_APPROVAL, o runtime
pausa e solicita decisão humana. Em exemplos e testes, o aprovador pode ser
simulado via configuração (auto_approve=True/False) para manter o determinismo.

Kill switch global: se o arquivo .kill_switch existir, TODAS as ações são
bloqueadas, independentemente de política ou aprovação.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field


class ApprovalDecision(str, Enum):
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    PENDING = "PENDING"


class ApprovalRequest(BaseModel):
    """Pedido de aprovação encaminhado ao aprovador humano."""

    request_id: str
    agent_id: str
    agent_name: str
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    reason: str  # motivo pelo qual a aprovação é necessária
    requested_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decision: ApprovalDecision = ApprovalDecision.PENDING
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_notes: Optional[str] = None


# Tipo para o callback do aprovador: recebe ApprovalRequest, retorna (bool, str)
ApproverCallback = Callable[[ApprovalRequest], tuple[bool, str]]


class KillSwitchActiveError(Exception):
    """Levantada quando o kill switch global está ativo."""

    pass


class ApprovalGate:
    """
    Gate de aprovação humana.

    Modos de operação:
    - interativo: solicita input via terminal (padrão em produção)
    - auto_approve: aprova automaticamente (para exemplos/testes)
    - auto_deny: nega automaticamente (para testes de rejeição)
    - callback: usa uma função fornecida pelo chamador
    """

    def __init__(
        self,
        kill_switch_path: str | Path = ".kill_switch",
        auto_approve: bool = False,
        auto_deny: bool = False,
        approver_callback: Optional[ApproverCallback] = None,
        interactive: bool = False,
    ) -> None:
        self._kill_switch_path = Path(kill_switch_path)
        self._auto_approve = auto_approve
        self._auto_deny = auto_deny
        self._approver_callback = approver_callback
        self._interactive = interactive
        self._pending: dict[str, ApprovalRequest] = {}

    def is_kill_switch_active(self) -> bool:
        """Verifica se o kill switch global está ativo."""
        return self._kill_switch_path.exists()

    def activate_kill_switch(self, reason: str = "activated by operator") -> None:
        """Ativa o kill switch, impedindo toda execução de agentes."""
        self._kill_switch_path.write_text(
            f"{datetime.now(timezone.utc).isoformat()} | {reason}\n"
        )

    def deactivate_kill_switch(self) -> None:
        """Desativa o kill switch."""
        if self._kill_switch_path.exists():
            os.remove(self._kill_switch_path)

    def check_kill_switch(self) -> None:
        """Levanta KillSwitchActiveError se o kill switch estiver ativo."""
        if self.is_kill_switch_active():
            reason = self._kill_switch_path.read_text().strip()
            raise KillSwitchActiveError(
                f"Kill switch ativo — todas as ações bloqueadas. Motivo: {reason}"
            )

    def request_approval(self, approval_req: ApprovalRequest) -> ApprovalRequest:
        """
        Solicita aprovação para uma ação de alto risco.

        Retorna o ApprovalRequest com a decisão preenchida.
        """
        self._pending[approval_req.request_id] = approval_req

        if self._auto_deny:
            return self._record_decision(approval_req, False, "auto-denied (configuração de teste)")

        if self._auto_approve:
            return self._record_decision(approval_req, True, "auto-approved (configuração de teste)")

        if self._approver_callback:
            approved, notes = self._approver_callback(approval_req)
            return self._record_decision(approval_req, approved, notes)

        if self._interactive:
            return self._interactive_approval(approval_req)

        # Fallback seguro: nega se nenhum mecanismo foi configurado
        return self._record_decision(
            approval_req, False, "nenhum aprovador configurado — negado por segurança"
        )

    def _interactive_approval(self, req: ApprovalRequest) -> ApprovalRequest:
        """Solicita aprovação via terminal (modo interativo)."""
        print("\n" + "=" * 60)
        print("  APROVACAO HUMANA NECESSARIA")
        print("=" * 60)
        print(f"  Agente   : {req.agent_name} ({req.agent_id})")
        print(f"  Ferramenta: {req.tool_name}")
        print(f"  Risco    : {req.risk_level.upper()}")
        print(f"  Motivo   : {req.reason}")
        if req.parameters:
            print(f"  Parametros: {req.parameters}")
        print("=" * 60)
        answer = input("  Aprovar? [s/N]: ").strip().lower()
        approved = answer in ("s", "sim", "y", "yes")
        notes = "aprovado pelo operador" if approved else "negado pelo operador"
        print("=" * 60 + "\n")
        return self._record_decision(req, approved, notes)

    def _record_decision(
        self, req: ApprovalRequest, approved: bool, notes: str
    ) -> ApprovalRequest:
        req.decision = ApprovalDecision.GRANTED if approved else ApprovalDecision.DENIED
        req.decided_at = datetime.now(timezone.utc).isoformat()
        req.decided_by = "human_approver"
        req.decision_notes = notes
        return req
