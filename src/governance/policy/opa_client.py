"""
OPA Policy Engine — cliente para Open Policy Agent.

Implementa a mesma interface do PolicyEngine YAML, permitindo trocar o
motor sem alterar o runtime.

Com OPA rodando (Docker Compose):
    engine = OpaPolicyEngine("http://localhost:8181", fallback=PolicyEngine(POLICIES_DIR))

Sem OPA (cai automaticamente no fallback YAML):
    engine = OpaPolicyEngine("http://localhost:8181", fallback=PolicyEngine(POLICIES_DIR))
    # → se OPA não responder, usa YAML silenciosamente

Referência: https://www.openpolicyagent.org/docs/latest/rest-api/
"""

from __future__ import annotations

import logging

import httpx

from governance.policy.engine import ActionRequest, PolicyDecision, PolicyEngine, PolicyResult

logger = logging.getLogger(__name__)

# Pacote Rego que as políticas devem usar (espelhado em docker/opa/policies/)
OPA_PACKAGE = "governance"
OPA_RULE = "decision"


class OpaPolicyEngine:
    """
    Motor de política que delega avaliação ao OPA via REST API.

    Fallback automático para PolicyEngine YAML se OPA não estiver disponível.
    Isso garante que o sistema funcione offline (dev) e em produção (OPA).
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        fallback: PolicyEngine | None = None,
        timeout_seconds: float = 1.0,
    ) -> None:
        self._opa_url = opa_url.rstrip("/")
        self._fallback = fallback
        self._timeout = timeout_seconds
        self._opa_available: bool | None = None  # None = não testado ainda
        self._client = httpx.Client(timeout=timeout_seconds)

    def _check_opa(self) -> bool:
        """Verifica se OPA está acessível (com cache simples)."""
        if self._opa_available is not None:
            return self._opa_available
        try:
            r = self._client.get(f"{self._opa_url}/health", timeout=0.5)
            self._opa_available = r.status_code == 200
        except Exception:
            self._opa_available = False
        return self._opa_available

    def evaluate(self, request: ActionRequest) -> PolicyResult:
        """Avalia via OPA, com fallback automático para YAML."""
        if self._check_opa():
            result = self._evaluate_opa(request)
            if result is not None:
                return result
            # OPA respondeu mas retornou resposta inesperada
            logger.warning("OPA retornou resposta inesperada — usando fallback YAML")

        if self._fallback:
            return self._fallback.evaluate(request)

        # Sem OPA e sem fallback: fail-closed (default-deny)
        return PolicyResult(
            decision=PolicyDecision.DENY,
            reason="Motor de política indisponível (OPA offline, sem fallback) — default-deny",
        )

    def _evaluate_opa(self, request: ActionRequest) -> PolicyResult | None:
        """Chama OPA REST API e interpreta a resposta."""
        input_data = {
            "input": {
                "agent_id": request.agent_id,
                "agent_name": request.agent_name,
                "tool_name": request.tool_name,
                "parameters": request.parameters,
                "environment": request.environment.value,
                "scopes": [s.value for s in request.scopes],
                "risk_level": request.risk_level.value,
            }
        }
        url = f"{self._opa_url}/v1/data/{OPA_PACKAGE}/{OPA_RULE}"
        try:
            r = self._client.post(url, json=input_data, timeout=self._timeout)
            if r.status_code != 200:
                logger.warning("OPA retornou HTTP %s", r.status_code)
                self._opa_available = False
                return None

            body = r.json()
            decision_str = body.get("result", "DENY")

            if not isinstance(decision_str, str):
                logger.warning("OPA retornou tipo inesperado para decision: %s", type(decision_str))
                return None

            decision = PolicyDecision(decision_str.upper())
            return PolicyResult(
                decision=decision,
                reason=f"Avaliado pelo OPA ({OPA_PACKAGE}/{OPA_RULE})",
                matched_rule=f"opa:{OPA_PACKAGE}.{OPA_RULE}",
                policy_file="opa",
            )
        except httpx.TimeoutException:
            logger.warning("OPA timeout após %.1fs — usando fallback", self._timeout)
            self._opa_available = False
            return None
        except Exception as e:
            logger.warning("Erro ao chamar OPA: %s — usando fallback", e)
            self._opa_available = False
            return None

    def reload(self) -> None:
        """Recarrega políticas (força re-checagem de disponibilidade do OPA)."""
        self._opa_available = None
        if self._fallback:
            self._fallback.reload()

    def reset_availability_cache(self) -> None:
        """Força re-checagem na próxima avaliação (útil após restart do OPA)."""
        self._opa_available = None
