# ADR-008 — Defesas da era agêntica (OWASP Top 10 for Agentic Applications)

**Status:** Aceito
**Data:** 2026-06-06
**Autores:** Time de Plataforma de IA

---

## Contexto

Os controles existentes (política, identidade, orçamento, auditoria, HITL, anomalia)
cobrem o que um agente está **autorizado** a fazer. Eles não cobrem uma classe de
ameaças específica de sistemas agênticos, formalizada pela **OWASP Top 10 for Agentic
Applications** (publicada em dezembro de 2025):

- **ASI01 Agent Goal Hijacking** — instruções maliciosas escondidas em conteúdo externo
  ou em saídas de ferramentas que sequestram o objetivo do agente (prompt injection indireto).
- **ASI04 Insecure Inter-Agent Communication** — mensagens entre agentes sem autenticidade,
  autorização ou proteção contra replay.
- **ASI06/ASI07 Tool Misuse & Agentic Supply Chain** — ferramentas/servidores MCP
  comprometidos, descrições "envenenadas" para enganar o agente (tool poisoning).
- **ASI09 Memory & Context Poisoning** — conteúdo não confiável persistido na memória
  que re-contamina o raciocínio em recuperações futuras.

Esses vetores não são endereçados por RBAC/política, porque a ação solicitada pode ser,
em si, "permitida" — o ataque está no **conteúdo** e na **proveniência**, não na autorização.

## Decisão

Adicionamos a Fase 8 com quatro defesas, plugáveis no `GovernedAgentRuntime` via
`GovernanceConfig` (campos opcionais, retrocompatíveis):

1. **Guardrails de conteúdo** (`src/governance/guardrails/`) — inspeção determinística
   de entrada e saída (prompt injection, jailbreak, unicode oculto, DLP de egress, secret
   leak), com hook LLM **opcional** desligado por padrão.
2. **Integridade de ferramentas + MCP** (`src/governance/supply_chain/`) — fingerprint
   assinada (Ed25519, reaproveitando o `AuditSigner`), detecção de drift/poisoning,
   allowlist de servidores MCP e geração de AI-BOM.
3. **Memória governada** (`src/governance/memory/`) — rótulos de confiança por proveniência
   e quarentena de conteúdo envenenado na recuperação (reusa os guardrails).
4. **Comunicação A2A assinada** (`src/governance/a2a/`) — mensagens Ed25519 com capability
   token (escopo + validade) e nonce anti-replay.

Além disso: alinhamento às **OTel GenAI Semantic Conventions** (`gen_ai.*`, aditivo) e
refresh de compliance (OWASP Agentic Top 10, EU AI Act GPAI, NIST GenAI Profile, model card).

## Motivação

### Por que guardrails determinísticos (e não LLM por padrão)?

O repositório roda 100% offline, sem chave de API, com testes reprodutíveis. Detectores
baseados em regras/heurísticas/regex entregam isso e cobrem a maioria dos padrões de injeção
conhecidos. O caminho de produção (classificador LLM, ex.: Llama Guard, Claude) é exposto
como interface plugável (`GuardrailScanner(llm_classifier=...)`), desligada por padrão.

### Por que fingerprint + assinatura para ferramentas?

Tool poisoning clássico reescreve a **descrição** de uma ferramenta para induzir o agente
a um comportamento malicioso — sem alterar a autorização. A fingerprint cobre metadados
(descrição, escopo, risco) e o código da implementação; a assinatura impede que um atacante
com acesso ao registro de pins forje um novo estado "confiável".

### Por que quarentena na recuperação (e não só na escrita)?

A memória pode ser escrita por muitos caminhos; centralizar a verificação no ponto de
**recuperação** garante que nenhum conteúdo não confiável volte ao contexto do agente,
independentemente de como entrou.

## Consequências

**Positivas:**
- Cobertura explícita do OWASP Agentic Top 10, verificada por 8 cenários adversariais (I–L).
- Tudo opcional e retrocompatível — runtime sem a config da Fase 8 é idêntico ao anterior.
- Interoperabilidade de observabilidade via `gen_ai.*` (Datadog/Honeycomb/Grafana/LangChain).

**Negativas / Limitações:**
- Guardrails determinísticos têm falsos negativos/positivos; o hook LLM é recomendado em prod.
- Fingerprint por código depende de `inspect.getsource`; quando indisponível (builtins/exec),
  cai para `module.qualname` — a detecção por **metadados** permanece robusta.
- Memória e nonces de A2A são mantidos em processo (produção: store durável + Redis para nonces).

## Pontos de extensão para produção

```python
# Guardrail com classificador LLM
def llm_guard(text, direction):
    verdict = call_llama_guard(text)  # ou Claude, Azure Content Safety...
    return GuardrailVerdict.BLOCK if verdict == "unsafe" else GuardrailVerdict.ALLOW

scanner = GuardrailScanner.with_defaults(llm_classifier=llm_guard)

# Assinatura de ferramentas via KMS (mesmo padrão do ADR-004)
integrity = ToolIntegrityRegistry(signer=KMSAuditSigner(...))
```
