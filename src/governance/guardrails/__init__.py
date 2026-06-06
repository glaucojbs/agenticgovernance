"""
Guardrails de conteúdo — defesa contra prompt injection, jailbreak e exfiltração.

Cobre OWASP Top 10 for Agentic Applications:
  - ASI01 Agent Goal Hijacking (prompt injection direto e indireto)
  - ASI06 Tool Misuse & Exploitation (exfiltração via tools de egress)
  - ASI05 Human-Agent Trust Exploitation

A camada inspeciona o conteúdo que entra (parâmetros, conteúdo externo,
saídas de tools) e decide ALLOW / FLAG / BLOCK por heurísticas determinísticas.
Opcionalmente, um classificador LLM pode ser plugado (desligado por padrão).
"""

from governance.guardrails.scanner import (
    DataExfiltrationDetector,
    GuardrailFinding,
    GuardrailResult,
    GuardrailScanner,
    GuardrailVerdict,
    PromptInjectionDetector,
    ScanDirection,
    SecretLeakDetector,
)

__all__ = [
    "DataExfiltrationDetector",
    "GuardrailFinding",
    "GuardrailResult",
    "GuardrailScanner",
    "GuardrailVerdict",
    "PromptInjectionDetector",
    "ScanDirection",
    "SecretLeakDetector",
]
