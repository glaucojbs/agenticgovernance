# 14: Camada LLM-Agnóstica

Este documento descreve a camada `governance.llm`, que materializa o contrato do
[ADR-009](adr/ADR-009-neutralidade-de-provedor-llm.md): o domínio de governança fala com
qualquer modelo de linguagem através de abstrações estáveis, sem depender de nenhum SDK de
fornecedor.

## Por quê

O runtime governa a **execução de ferramentas**. Mas a **chamada de inferência ao LLM** também
é uma ação governável: ela tem custo, consome tokens, pode receber prompt injection na entrada
e vazar segredos/PII na saída, e precisa de trilha de auditoria. Sem uma camada própria, cada
integração reescreveria esses controles — e acoplaria o domínio a um fornecedor específico.

## Contrato neutro

Em `governance.llm.provider`:

| Tipo | Papel |
|------|-------|
| `LlmMessage` | Mensagem `{role, content}`, neutra a provedor |
| `LlmRequest` | `model`, `messages`, `max_tokens`, `temperature`, `metadata` |
| `LlmResponse` | `text`, `model`, `provider`, `usage`, `finish_reason` |
| `LlmUsage` | `input_tokens`, `output_tokens` |
| `LlmProvider` | `Protocol` `@runtime_checkable`: `name` + `complete(request) -> LlmResponse` |

O domínio depende apenas dessas abstrações. Qualquer objeto com `name` e `complete()` é um
provedor válido (`isinstance(obj, LlmProvider)` funciona por ser um Protocol).

## Provedores

- **`MockLlmProvider`** (`governance.llm.mock`) — offline e determinístico. Suporta respostas
  roteiradas (`scripted=[...]`) ou um `responder` callable. É o provedor padrão de testes e
  exemplos; mantém o repositório executável sem rede e sem chave de API.

- **Adapters** (`governance.llm.adapters`) — `AnthropicAdapter`, `OpenAIAdapter`,
  `AzureOpenAIAdapter`, `OllamaAdapter`. Cada um importa o SDK do fornecedor **preguiçosamente**,
  dentro de `complete()`. Os SDKs são extras opcionais do `pyproject.toml`:

  ```bash
  pip install 'agentic-governance[anthropic]'   # ou [openai], [azure], [ollama]
  ```

  Para testes sem rede, um cliente já construído pode ser injetado: `OpenAIAdapter(client=fake)`.

## Inferência governada

`GovernedLlmProvider` (`governance.llm.governed`) envolve qualquer `LlmProvider` e roteia
`complete()` por seis estágios:

1. **Guardrails de entrada** — `GuardrailScanner.scan_text(prompt, INPUT)`; se bloqueado, audita
   `guardrail_blocked` e levanta `LlmGuardrailError` **antes** de gastar qualquer token.
2. **Orçamento** — estima tokens/custo e chama `BudgetGuard.check_and_consume`; em estouro,
   audita `budget_exceeded` e propaga `BudgetExceededError`.
3. **Inferência** — delega ao provedor concreto.
4. **Guardrails de saída** — `scan_text(resposta, OUTPUT)`; bloqueia vazamento de segredo/PII.
5. **Telemetria** — span OTel com atributos `gen_ai.*` (`set_llm_span_attributes`).
6. **Auditoria** — evento `llm_invoked` na cadeia de hash, com provider, modelo e tokens.

Todos os controles são injetados e opcionais. Com todos `None`, o wrapper apenas delega.

```python
from governance.llm import GovernedLlmProvider, MockLlmProvider, LlmRequest, LlmMessage
from governance.budget.guard import BudgetGuard
from governance.guardrails.scanner import GuardrailScanner
from governance.audit.logger import AuditLogger

governed = GovernedLlmProvider(
    MockLlmProvider(),                       # troque por um adapter real sem mudar nada abaixo
    budget=BudgetGuard(),
    guardrails=GuardrailScanner.with_defaults(),
    audit=AuditLogger("audit_logs/llm.jsonl"),
)

resp = governed.complete(
    LlmRequest(model="mock-1", messages=[LlmMessage(role="user", content="olá")]),
    agent_id="assistant-1",
)
```

## Conformidade de adapter

`tests/test_llm_conformance.py` aplica o mesmo conjunto de asserções de contrato ao mock e a
cada adapter (com clientes falsos). Qualquer novo provedor deve passar nessa suíte para garantir
paridade de comportamento. Para adicionar um provedor:

1. Crie `governance/llm/adapters/<nome>_adapter.py` implementando `LlmProvider` com import lazy.
2. Exporte-o em `governance/llm/adapters/__init__.py`.
3. Adicione o extra em `pyproject.toml`.
4. Registre uma factory na suíte de conformidade.

## Veja também

- Exemplo executável: `examples/13_llm_provider` (`python -m examples.13_llm_provider`).
- [ADR-009](adr/ADR-009-neutralidade-de-provedor-llm.md) — decisão de neutralidade.
- [11-guardrails-e-conteudo](11-guardrails-e-conteudo.md) — detectores reutilizados aqui.
