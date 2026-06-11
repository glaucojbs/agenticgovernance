"""
NApprovalGate — aprovação M-de-N com timeout.

Para operações críticas (risco CRITICAL), exige que M aprovadores
de um conjunto de N confirme a ação antes de executar.

Exemplos de uso real:
  - Wipe de banco de dados: 2 de 3 engenheiros seniores
  - Deploy em produção: 1 eng + 1 security engineer
  - Revogação em massa de credenciais: 2 managers

Em produção, integrar com:
  - PagerDuty multi-responder
  - Slack approval workflow com múltiplos usuários
  - Jira approval com SLA tracking
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class VoteDecision(StrEnum):
    APPROVE = "approve"
    DENY = "deny"


class ApproverVote(BaseModel):
    approver_id: str
    approver_name: str
    decision: VoteDecision
    notes: str = ""
    voted_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class NApprovalRequest(BaseModel):
    request_id: str
    agent_id: str
    agent_name: str
    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: str
    reason: str
    required_approvals: int  # M — quantos votos APPROVE são necessários
    available_approvers: list[str]  # nomes dos N aprovadores disponíveis
    timeout_seconds: float
    requested_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    votes: list[ApproverVote] = Field(default_factory=list)

    @property
    def approve_count(self) -> int:
        return sum(1 for v in self.votes if v.decision == VoteDecision.APPROVE)

    @property
    def deny_count(self) -> int:
        return sum(1 for v in self.votes if v.decision == VoteDecision.DENY)

    @property
    def is_granted(self) -> bool:
        return self.approve_count >= self.required_approvals

    @property
    def is_denied(self) -> bool:
        # Negado se votos negativos suficientes para impossibilitar atingir M
        remaining_approvers = len(self.available_approvers) - len(self.votes)
        max_possible = self.approve_count + remaining_approvers
        return max_possible < self.required_approvals or self.deny_count > 0

    def vote_summary(self) -> str:
        return (
            f"{self.approve_count}/{self.required_approvals} aprovações, "
            f"{self.deny_count} negações, "
            f"{len(self.available_approvers) - len(self.votes)} pendentes"
        )


# Callback: recebe o request, deve retornar list[ApproverVote]
NApproverCallback = Callable[[NApprovalRequest], list[ApproverVote]]


class NApprovalGate:
    """
    Gate de aprovação M-de-N com timeout.

    Simula múltiplos aprovadores independentes. Em produção, cada
    approver_callback dispara uma notificação diferente (Slack DM,
    PagerDuty alert, e-mail) e coleta a resposta de forma assíncrona.
    """

    def __init__(
        self,
        required_approvals: int = 2,
        available_approvers: list[str] | None = None,
        timeout_seconds: float = 300.0,
        approver_callbacks: list[NApproverCallback] | None = None,
        auto_approve_count: int = 0,  # para testes
        auto_deny_count: int = 0,  # para testes
    ) -> None:
        self._required = required_approvals
        self._approvers = available_approvers or [
            f"approver-{i}" for i in range(1, required_approvals + 2)
        ]
        self._timeout = timeout_seconds
        self._callbacks = approver_callbacks or []
        self._auto_approve = auto_approve_count
        self._auto_deny = auto_deny_count

    def request_approval(
        self,
        agent_id: str,
        agent_name: str,
        tool_name: str,
        parameters: dict[str, Any],
        risk_level: str,
        reason: str,
    ) -> NApprovalRequest:
        """Solicita aprovação M-de-N e retorna com os votos coletados."""
        req = NApprovalRequest(
            request_id=secrets.token_hex(8),
            agent_id=agent_id,
            agent_name=agent_name,
            tool_name=tool_name,
            parameters=parameters,
            risk_level=risk_level,
            reason=reason,
            required_approvals=self._required,
            available_approvers=self._approvers,
            timeout_seconds=self._timeout,
        )

        # Coleta votos automáticos (para testes/exemplos)
        for i in range(self._auto_approve):
            req.votes.append(
                ApproverVote(
                    approver_id=f"auto-approver-{i + 1}",
                    approver_name=f"Auto Approver {i + 1}",
                    decision=VoteDecision.APPROVE,
                    notes="auto-approved (test mode)",
                )
            )

        for i in range(self._auto_deny):
            req.votes.append(
                ApproverVote(
                    approver_id=f"auto-denier-{i + 1}",
                    approver_name=f"Auto Denier {i + 1}",
                    decision=VoteDecision.DENY,
                    notes="auto-denied (test mode)",
                )
            )

        # Chama callbacks de aprovadores reais
        for callback in self._callbacks:
            try:
                votes = callback(req)
                req.votes.extend(votes)
                if req.is_granted or req.is_denied:
                    break
            except Exception:
                pass

        return req
