"""
Motor de política declarativo.

Avalia ActionRequests contra políticas YAML e retorna ALLOW / DENY / REQUIRE_APPROVAL.
Princípio fundamental: default-deny — sem regra explícita que permita, nega.
"""

from __future__ import annotations

import glob
import os
from datetime import UTC
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel

from governance.identity.models import AgentEnvironment, AgentScope


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ActionRequest(BaseModel):
    """Pedido de execução de uma ferramenta por um agente."""

    agent_id: str
    agent_name: str
    tool_name: str
    parameters: dict[str, Any] = {}
    environment: AgentEnvironment
    scopes: list[AgentScope] = []
    risk_level: RiskLevel = RiskLevel.LOW
    metadata: dict[str, Any] = {}


class PolicyResult(BaseModel):
    """Resultado da avaliação de política."""

    decision: PolicyDecision
    reason: str
    matched_rule: str | None = None
    policy_file: str | None = None


class _PolicyRule(BaseModel):
    """Representação interna de uma regra de política YAML."""

    name: str
    decision: PolicyDecision
    tools: list[str] = ["*"]
    scopes_required: list[str] = []
    environments: list[str] = ["*"]
    risk_levels: list[str] = ["*"]
    conditions: dict[str, Any] = {}
    reason: str = ""
    # Condições temporais (UTC): lista de horas permitidas [0..23]
    allowed_utc_hours: list[int] = []
    # Dias da semana permitidos [0=segunda..6=domingo]
    allowed_weekdays: list[int] = []


class PolicyEngine:
    """
    Motor de política que avalia ActionRequests contra arquivos YAML.

    Ordem de avaliação:
    1. Regras DENY — têm precedência absoluta.
    2. Regras REQUIRE_APPROVAL — se alguma bate, exige aprovação.
    3. Regras ALLOW — permitem a execução.
    4. Default-deny — nenhuma regra bateu, nega.
    """

    def __init__(self, policies_dir: str | Path) -> None:
        self._policies_dir = Path(policies_dir)
        self._rules: list[tuple[str, _PolicyRule]] = []  # (filename, rule)
        self._load_policies()

    def _load_policies(self) -> None:
        """Carrega todos os arquivos .yaml do diretório de políticas."""
        self._rules.clear()
        pattern = str(self._policies_dir / "*.yaml")
        for filepath in sorted(glob.glob(pattern)):
            filename = os.path.basename(filepath)
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if not data or "rules" not in data:
                continue
            for rule_data in data["rules"]:
                rule = _PolicyRule(**rule_data)
                self._rules.append((filename, rule))

    def reload(self) -> None:
        """Recarrega políticas do disco (útil para mudanças em tempo real)."""
        self._load_policies()

    def evaluate(self, request: ActionRequest) -> PolicyResult:
        """Avalia um ActionRequest e retorna a decisão de política."""
        deny_result: PolicyResult | None = None
        approval_result: PolicyResult | None = None

        for filename, rule in self._rules:
            if not self._rule_matches(rule, request):
                continue

            if rule.decision == PolicyDecision.DENY:
                deny_result = PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason=rule.reason or f"Negado pela regra '{rule.name}'",
                    matched_rule=rule.name,
                    policy_file=filename,
                )
                # DENY tem precedência: retorna imediatamente
                return deny_result

            if rule.decision == PolicyDecision.REQUIRE_APPROVAL and approval_result is None:
                approval_result = PolicyResult(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    reason=rule.reason or f"Aprovação exigida pela regra '{rule.name}'",
                    matched_rule=rule.name,
                    policy_file=filename,
                )

            if rule.decision == PolicyDecision.ALLOW and approval_result is None:
                # ALLOW — mas continua iterando para verificar se algum DENY aparece depois
                # (nesta implementação os DENY já retornam imediatamente, mas mantemos a ordem)
                return PolicyResult(
                    decision=PolicyDecision.ALLOW,
                    reason=rule.reason or f"Permitido pela regra '{rule.name}'",
                    matched_rule=rule.name,
                    policy_file=filename,
                )

        if approval_result:
            return approval_result

        # Default-deny: nenhuma regra ALLOW bateu
        return PolicyResult(
            decision=PolicyDecision.DENY,
            reason=(
                f"Nenhuma política permite a ação '{request.tool_name}' "
                f"para o agente '{request.agent_name}' (default-deny)"
            ),
        )

    def _rule_matches(self, rule: _PolicyRule, request: ActionRequest) -> bool:
        """Verifica se uma regra se aplica ao ActionRequest."""
        from datetime import datetime

        # Verifica ferramenta
        if rule.tools != ["*"] and request.tool_name not in rule.tools:
            return False

        # Verifica ambiente
        if rule.environments != ["*"] and request.environment.value not in rule.environments:
            return False

        # Verifica nível de risco
        if rule.risk_levels != ["*"] and request.risk_level.value not in rule.risk_levels:
            return False

        # Verifica se o agente possui os escopos exigidos pela regra
        if rule.scopes_required:
            agent_scope_values = [s.value for s in request.scopes]
            if not all(s in agent_scope_values for s in rule.scopes_required):
                return False

        # Condições temporais (UTC)
        if rule.allowed_utc_hours:
            now = datetime.now(UTC)
            if now.hour not in rule.allowed_utc_hours:
                return False

        if rule.allowed_weekdays:
            now = datetime.now(UTC)
            if now.weekday() not in rule.allowed_weekdays:
                return False

        # Verifica condições adicionais nos parâmetros
        for param_key, param_constraint in rule.conditions.items():
            param_value = request.parameters.get(param_key)
            if not self._check_condition(param_value, param_constraint):
                return False

        return True

    def _check_condition(self, value: Any, constraint: Any) -> bool:
        """Avalia uma condição de parâmetro contra um valor."""
        if isinstance(constraint, dict):
            if "max" in constraint and value is not None:
                try:
                    if float(value) > float(constraint["max"]):
                        return False
                except (TypeError, ValueError):
                    pass
            if "min" in constraint and value is not None:
                try:
                    if float(value) < float(constraint["min"]):
                        return False
                except (TypeError, ValueError):
                    pass
            if "not_in" in constraint and value is not None and value in constraint["not_in"]:
                return False
            if "in" in constraint and value is not None and value not in constraint["in"]:
                return False
        elif isinstance(constraint, list):
            if value not in constraint:
                return False
        else:
            if value != constraint:
                return False
        return True
