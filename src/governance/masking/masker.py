"""
PIIMasker — redação de dados pessoais no audit log.

Aplica padrões regex configuráveis sobre os campos de texto dos eventos
de auditoria antes de gravá-los. Garante que dados sensíveis (CPF, e-mail,
telefone, tokens, cartões) não apareçam em texto claro nos logs.

Em produção, complementar com:
  - Tokenização via Vault Transit
  - Mascaramento na camada de ingestão (Kafka → Flink)
  - Column-level encryption no Iceberg
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class MaskingPattern(StrEnum):
    """Padrões de PII pré-definidos."""

    EMAIL = "email"
    CPF = "cpf"
    CNPJ = "cnpj"
    PHONE_BR = "phone_br"
    CREDIT_CARD = "credit_card"
    JWT_TOKEN = "jwt_token"
    API_KEY = "api_key"
    IP_ADDRESS = "ip_address"


_BUILTIN_PATTERNS: dict[MaskingPattern, str] = {
    MaskingPattern.EMAIL: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    MaskingPattern.CPF: r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
    MaskingPattern.CNPJ: r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b",
    MaskingPattern.PHONE_BR: r"\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)(?:9\s?)?\d{4}[\s\-]?\d{4}\b",
    MaskingPattern.CREDIT_CARD: r"\b(?:\d[ \-]?){13,19}\b",
    MaskingPattern.JWT_TOKEN: r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    MaskingPattern.API_KEY: r"\b(?:sk|pk|api|key|token|secret)[_\-]?[A-Za-z0-9]{20,}\b",
    MaskingPattern.IP_ADDRESS: r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
}


@dataclass
class MaskingRule:
    """Uma regra de mascaramento: padrão regex → texto de substituição."""

    pattern: str
    replacement: str = "[REDACTED]"
    name: str = ""

    def __post_init__(self) -> None:
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def apply(self, text: str) -> str:
        return self._compiled.sub(self.replacement, text)

    def matches(self, text: str) -> bool:
        """Retorna True se o padrão casa em algum trecho do texto (sem mascarar)."""
        return bool(self._compiled.search(text))


class PIIMasker:
    """
    Aplica redação de PII sobre dicts de detalhes de eventos de auditoria.

    Uso:
        masker = PIIMasker.with_defaults()
        masked = masker.mask_details({"query": "SELECT * FROM users WHERE email='foo@bar.com'"})
        # → {"query": "SELECT * FROM users WHERE email='[EMAIL]'"}
    """

    def __init__(self, rules: list[MaskingRule] | None = None) -> None:
        self._rules: list[MaskingRule] = rules or []

    @classmethod
    def with_defaults(cls) -> PIIMasker:
        """Cria um masker com todos os padrões built-in."""
        rules = [
            MaskingRule(
                pattern=regex,
                replacement=f"[{pattern.upper()}]",
                name=pattern.value,
            )
            for pattern, regex in _BUILTIN_PATTERNS.items()
        ]
        return cls(rules)

    @classmethod
    def with_patterns(cls, *patterns: MaskingPattern) -> PIIMasker:
        """Cria um masker com apenas os padrões selecionados."""
        rules = [
            MaskingRule(
                pattern=_BUILTIN_PATTERNS[p],
                replacement=f"[{p.upper()}]",
                name=p.value,
            )
            for p in patterns
        ]
        return cls(rules)

    def add_rule(self, pattern: str, replacement: str = "[REDACTED]", name: str = "") -> None:
        """Adiciona uma regra personalizada."""
        self._rules.append(MaskingRule(pattern=pattern, replacement=replacement, name=name))

    def mask_string(self, text: str) -> str:
        for rule in self._rules:
            text = rule.apply(text)
        return text

    def find_matches(self, text: str) -> list[str]:
        """Retorna os nomes das regras cujo padrão casa no texto (detecção, não redação).

        Usado por detectores de DLP/exfiltração para reaproveitar os padrões de PII
        sem mascarar o conteúdo.
        """
        return [rule.name or rule.pattern for rule in self._rules if rule.matches(text)]

    def mask_details(self, details: dict[str, Any]) -> dict[str, Any]:
        """Aplica mascaramento recursivo sobre um dict de detalhes."""
        return self._mask_value(details)

    def _mask_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.mask_string(value)
        if isinstance(value, dict):
            return {k: self._mask_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._mask_value(item) for item in value]
        # Serializa tipos complexos para string antes de mascarar
        if not isinstance(value, (int, float, bool, type(None))):
            try:
                serialized = json.dumps(value, default=str)
                masked = self.mask_string(serialized)
                return json.loads(masked)
            except Exception:
                return str(value)
        return value
