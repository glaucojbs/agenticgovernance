# 13 — Memória Governada e Comunicação A2A

> Defesa contra memory poisoning e comunicação inter-agente insegura.
> Cobre **OWASP ASI09 (Memory & Context Poisoning)** e **ASI04 (Insecure Inter-Agent
> Communication)**.

---

## Parte A — Memória governada

### O problema

Agentes mantêm memória/contexto entre passos. Se conteúdo não confiável (e-mail, página,
saída de ferramenta) é persistido sem rótulo, ele pode **re-contaminar** o raciocínio em
recuperações futuras — uma injeção que "dorme" na memória e ataca depois.

### A solução

`GovernedMemoryStore` (`src/governance/memory/store.py`) atribui um **rótulo de confiança**
por proveniência e faz **quarentena na recuperação**:

| Origem | Rótulo inicial |
|--------|----------------|
| `USER` (operador) | TRUSTED |
| `AGENT` (raciocínio próprio) | TRUSTED |
| `TOOL` (saída de ferramenta) | UNTRUSTED |
| `EXTERNAL` (e-mail, web, doc) | UNTRUSTED |

```python
store = GovernedMemoryStore(scanner=GuardrailScanner.with_defaults(), audit=audit)
store.write("agent", email_body, MemoryOrigin.EXTERNAL)
safe = store.retrieve("agent")   # conteúdo UNTRUSTED passa pelos guardrails
```

Na recuperação, todo conteúdo UNTRUSTED é varrido pelos [guardrails](11-guardrails-e-conteudo.md).
Se contiver injeção, a entrada vira `QUARANTINED`, é registrada como `MEMORY_QUARANTINED`
no audit log e **não volta** ao agente. Conteúdo confiável (ou não confiável porém limpo)
é retornado normalmente.

A verificação centralizada **no ponto de recuperação** garante cobertura independentemente
de como o conteúdo entrou na memória.

## Parte B — Comunicação A2A assinada

### O problema

Em sistemas multi-agente, um agente delega tarefas a outro. Sem proteção, um atacante pode
**forjar**, **adulterar** ou **reproduzir (replay)** mensagens entre agentes, ou um agente
pode receber ordens de uma origem não autenticada.

### A solução

`SignedAgentChannel` (`src/governance/a2a/channel.py`). Cada mensagem:

- é **assinada** com a chave Ed25519 do remetente (autenticidade + integridade);
- carrega um **CapabilityToken** com escopos e validade (autorização mínima);
- tem um **nonce** único (proteção contra replay).

```python
channel = SignedAgentChannel(audit=audit)
channel.register_agent("orchestrator", orch_signer.public_key_pem())

msg = channel.send("orchestrator", orch_signer, "worker",
                   {"task": "fetch"}, scopes=["read:database"])
channel.receive(msg, required_scope="read:database").accepted  # True
```

O receptor valida, nesta ordem: **remetente registrado → assinatura → expiração → nonce
não reutilizado → escopo exigido**. Qualquer falha gera `A2A_MESSAGE_REJECTED` no audit log.

| Ataque | Resultado |
|--------|-----------|
| Mensagem de remetente desconhecido | rejeitada (não registrado) |
| Payload adulterado após assinar | rejeitada (assinatura inválida) |
| Token vencido | rejeitada (expirado) |
| Mesma mensagem reenviada | rejeitada (replay/nonce) |
| Escopo exigido ausente no token | rejeitada |

## Demonstração

```bash
python -m examples.11_memory_a2a
```

## Limitações

- Memória e nonces ficam em processo; em produção use store durável + Redis para nonces
  (com TTL alinhado à validade do token).
- O canal cobre integridade/autorização de mensagens, não o transporte (use mTLS na rede).

Relacionado: [11 — Guardrails](11-guardrails-e-conteudo.md),
[03 — Identidade e acesso](03-identidade-e-acesso.md),
[ADR-008](adr/ADR-008-defesas-agenticas.md).
