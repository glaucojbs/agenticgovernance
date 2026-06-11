"""
Scanner de guardrails — inspeção determinística de conteúdo.

Cada detector recebe um texto e a direção (input/output) e devolve achados
(`GuardrailFinding`). O scanner agrega os achados e produz o veredito mais
severo (ALLOW < FLAG < BLOCK).

Detectores determinísticos (sem rede, testes reprodutíveis):
  - PromptInjectionDetector  — injeção direta/indireta de instruções, jailbreak
  - DataExfiltrationDetector — PII/segredos saindo por ferramentas de egress (DLP)
  - SecretLeakDetector       — chaves e segredos vazando em saídas de ferramentas

Hook opcional `llm_classifier` permite plugar um classificador LLM em produção;
fica desligado por padrão para preservar o caráter offline do repositório.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from governance.masking.masker import PIIMasker


class GuardrailVerdict(StrEnum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class ScanDirection(StrEnum):
    INPUT = "input"  # parâmetros / conteúdo externo entrando no agente
    OUTPUT = "output"  # saída de uma ferramenta antes de voltar ao agente


_VERDICT_ORDER: dict[GuardrailVerdict, int] = {
    GuardrailVerdict.ALLOW: 0,
    GuardrailVerdict.FLAG: 1,
    GuardrailVerdict.BLOCK: 2,
}


def _worst(a: GuardrailVerdict, b: GuardrailVerdict) -> GuardrailVerdict:
    return a if _VERDICT_ORDER[a] >= _VERDICT_ORDER[b] else b


@dataclass
class GuardrailFinding:
    """Um achado individual de um detector."""

    detector: str
    verdict: GuardrailVerdict
    rule: str
    message: str
    snippet: str = ""


@dataclass
class GuardrailResult:
    """Resultado agregado de uma varredura."""

    verdict: GuardrailVerdict
    direction: ScanDirection
    findings: list[GuardrailFinding] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict == GuardrailVerdict.BLOCK

    @property
    def flagged(self) -> bool:
        return self.verdict == GuardrailVerdict.FLAG

    @property
    def clean(self) -> bool:
        return self.verdict == GuardrailVerdict.ALLOW

    def summary(self) -> str:
        if self.clean:
            return "sem achados"
        rules = ", ".join(sorted({f.rule for f in self.findings}))
        return f"{self.verdict.value}: {rules}"


# ── Detectores ─────────────────────────────────────────────────────────────────


class Detector:
    """Base de um detector de guardrail."""

    name: str = "detector"

    def scan(
        self,
        text: str,
        direction: ScanDirection,
        *,
        tool_name: str | None = None,
    ) -> list[GuardrailFinding]:
        raise NotImplementedError


# Marcadores zero-width / bidi usados para esconder instrucoes no texto:
# zero-width space..RTL mark, bidi embedding/override, word joiner.., BOM.
_HIDDEN_RANGES = ((0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0xFEFF, 0xFEFF))
_HIDDEN_UNICODE = re.compile(
    "[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _HIDDEN_RANGES) + "]"
)

_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (
        "ignore_previous",
        r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|all)\b"
        r".{0,30}\b(instruction|instructions|prompt|prompts|message|messages|rule|rules|context)\b",
    ),
    ("role_marker", r"(?im)^\s*(system|assistant|developer)\s*:"),
    ("chat_template", r"<\|(im_start|im_end|system|assistant)\|>|\[/?INST\]|</s>"),
    ("override_system", r"\b(new|updated|real)\s+(system\s+)?(prompt|instructions?)\b"),
    ("reveal_prompt", r"\b(reveal|show|print|repeat|leak)\b.{0,30}\b(system\s+)?prompt\b"),
    ("jailbreak_persona", r"\b(DAN\s+mode|developer\s+mode|do\s+anything\s+now|jailbreak)\b"),
    (
        "act_as",
        r"\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\b.{0,40}\b(no\s+restrictions?|unrestricted|admin|root)\b",
    ),
    (
        "exfil_instruction",
        r"\b(send|forward|exfiltrate|upload|post)\b.{0,30}\b(to|email|webhook|url|http)\b.{0,40}\b(secret|password|token|key|credential|data)\b",
    ),
]


class PromptInjectionDetector(Detector):
    """Detecta injeção de instruções (direta e indireta) e jailbreak.

    Injeção *indireta* é a mais perigosa para agentes: instruções escondidas
    em conteúdo externo (e-mails, páginas, documentos) ou em saídas de tools
    que tentam sequestrar o objetivo do agente (OWASP ASI01 Goal Hijacking).
    """

    name = "prompt_injection"

    def __init__(self) -> None:
        self._patterns = [(name, re.compile(rx, re.IGNORECASE)) for name, rx in _INJECTION_PATTERNS]

    def scan(
        self,
        text: str,
        direction: ScanDirection,
        *,
        tool_name: str | None = None,
    ) -> list[GuardrailFinding]:
        findings: list[GuardrailFinding] = []
        for rule_name, rx in self._patterns:
            match = rx.search(text)
            if match:
                findings.append(
                    GuardrailFinding(
                        detector=self.name,
                        verdict=GuardrailVerdict.BLOCK,
                        rule=rule_name,
                        message=f"Padrão de injeção '{rule_name}' detectado ({direction.value})",
                        snippet=match.group(0)[:80],
                    )
                )
        if _HIDDEN_UNICODE.search(text):
            findings.append(
                GuardrailFinding(
                    detector=self.name,
                    verdict=GuardrailVerdict.BLOCK,
                    rule="hidden_unicode",
                    message="Caracteres unicode ocultos (zero-width/bidi) — possível injeção camuflada",
                )
            )
        return findings


_DEFAULT_EGRESS_TOOLS = frozenset(
    {"send_email", "http_post", "call_external_api", "post_webhook", "upload_file"}
)


class DataExfiltrationDetector(Detector):
    """DLP de egress: bloqueia PII/segredos saindo por ferramentas externas.

    Reaproveita os padrões do `PIIMasker`. Em parâmetros de uma ferramenta de
    egress, dado sensível vira BLOCK; em outros contextos, FLAG.
    """

    name = "data_exfiltration"

    def __init__(
        self,
        masker: PIIMasker | None = None,
        egress_tools: frozenset[str] | None = None,
    ) -> None:
        self._masker = masker or PIIMasker.with_defaults()
        self._egress = egress_tools or _DEFAULT_EGRESS_TOOLS

    def scan(
        self,
        text: str,
        direction: ScanDirection,
        *,
        tool_name: str | None = None,
    ) -> list[GuardrailFinding]:
        matched = self._masker.find_matches(text)
        if not matched:
            return []
        is_egress = direction == ScanDirection.INPUT and tool_name in self._egress
        verdict = GuardrailVerdict.BLOCK if is_egress else GuardrailVerdict.FLAG
        where = f" via ferramenta de egress '{tool_name}'" if is_egress else ""
        return [
            GuardrailFinding(
                detector=self.name,
                verdict=verdict,
                rule="sensitive_egress",
                message=f"Dado sensível ({', '.join(matched)}) detectado{where}",
            )
        ]


_SECRET_PATTERNS: list[tuple[str, str]] = [
    ("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
    ("private_key_block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("openai_key", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("github_token", r"\bghp_[A-Za-z0-9]{20,}\b"),
    ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("bearer_token", r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b"),
]


class SecretLeakDetector(Detector):
    """Detecta segredos vazando em saídas de ferramentas (OWASP ASI06)."""

    name = "secret_leak"

    def __init__(self) -> None:
        self._patterns = [(name, re.compile(rx)) for name, rx in _SECRET_PATTERNS]

    def scan(
        self,
        text: str,
        direction: ScanDirection,
        *,
        tool_name: str | None = None,
    ) -> list[GuardrailFinding]:
        findings: list[GuardrailFinding] = []
        verdict = (
            GuardrailVerdict.BLOCK if direction == ScanDirection.OUTPUT else GuardrailVerdict.FLAG
        )
        for rule_name, rx in self._patterns:
            if rx.search(text):
                findings.append(
                    GuardrailFinding(
                        detector=self.name,
                        verdict=verdict,
                        rule=rule_name,
                        message=f"Segredo '{rule_name}' detectado em {direction.value}",
                    )
                )
        return findings


# ── Scanner ──────────────────────────────────────────────────────────────────

LlmClassifier = Callable[[str, ScanDirection], GuardrailVerdict]


class GuardrailScanner:
    """Agrega detectores e produz um veredito por varredura.

    Uso:
        scanner = GuardrailScanner.with_defaults()
        result = scanner.scan_parameters({"body": "ignore previous instructions"})
        if result.blocked:
            ...
    """

    def __init__(
        self,
        detectors: list[Detector] | None = None,
        llm_classifier: LlmClassifier | None = None,
    ) -> None:
        self._detectors = detectors if detectors is not None else []
        self._llm = llm_classifier

    @classmethod
    def with_defaults(
        cls,
        *,
        masker: PIIMasker | None = None,
        egress_tools: frozenset[str] | None = None,
        llm_classifier: LlmClassifier | None = None,
    ) -> GuardrailScanner:
        """Cria um scanner com os três detectores determinísticos."""
        return cls(
            detectors=[
                PromptInjectionDetector(),
                DataExfiltrationDetector(masker=masker, egress_tools=egress_tools),
                SecretLeakDetector(),
            ],
            llm_classifier=llm_classifier,
        )

    def scan_text(
        self,
        text: str,
        direction: ScanDirection,
        *,
        tool_name: str | None = None,
    ) -> GuardrailResult:
        findings: list[GuardrailFinding] = []
        verdict = GuardrailVerdict.ALLOW
        for detector in self._detectors:
            for finding in detector.scan(text, direction, tool_name=tool_name):
                findings.append(finding)
                verdict = _worst(verdict, finding.verdict)

        # Hook LLM opcional (desligado por padrão; nunca chamado nos testes base)
        if self._llm is not None:
            llm_verdict = self._llm(text, direction)
            if llm_verdict != GuardrailVerdict.ALLOW:
                findings.append(
                    GuardrailFinding(
                        detector="llm_classifier",
                        verdict=llm_verdict,
                        rule="llm",
                        message=f"Classificador LLM retornou {llm_verdict.value}",
                    )
                )
                verdict = _worst(verdict, llm_verdict)

        return GuardrailResult(verdict=verdict, direction=direction, findings=findings)

    def scan_parameters(
        self,
        parameters: dict[str, object],
        *,
        tool_name: str | None = None,
    ) -> GuardrailResult:
        """Varre os parâmetros de entrada de uma ferramenta (direção INPUT)."""
        return self.scan_text(_stringify(parameters), ScanDirection.INPUT, tool_name=tool_name)

    def scan_output(
        self,
        output: object,
        *,
        tool_name: str | None = None,
    ) -> GuardrailResult:
        """Varre a saída de uma ferramenta (direção OUTPUT)."""
        return self.scan_text(_stringify(output), ScanDirection.OUTPUT, tool_name=tool_name)


def _stringify(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(f"{k} {_stringify(v)}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return " ".join(_stringify(v) for v in value)
    return str(value)
