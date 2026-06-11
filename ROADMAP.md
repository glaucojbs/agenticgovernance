# Roadmap

Backlog temático e priorizado deste repositório. É a **fonte única** do que vem a seguir.
A evolução acontece em **incrementos diários pequenos** (um PR por dia), preservando o
[Contrato de Neutralidade](AGENTS.md) e as barreiras de governança existentes.

## Como este roadmap funciona

- **Cadência**: um incremento pequeno e mergeável por dia.
- **Fluxo híbrido**: um agente seleciona o próximo item desbloqueado de maior prioridade,
  **propõe** a abordagem e **aguarda aprovação humana** antes de implementar e abrir o PR.
  Detalhes em [`CONTRIBUTING.md`](CONTRIBUTING.md#fluxo-de-melhoria-diária).
- **Seleção**: sempre o **primeiro item não-feito de maior prioridade** que esteja
  desbloqueado. Itens são reordenáveis.
- **Registro**: cada incremento marca o item aqui (`- [ ]` → `- [x]`) e adiciona uma linha
  ao [`CHANGELOG.md`](CHANGELOG.md).
- **Definição de Pronto**: ver [`CONTRIBUTING.md`](CONTRIBUTING.md#definição-de-pronto-de-um-incremento-diário).

Esforço: 🟢 pequeno (1 dia) · 🟡 médio (pode virar 2 dias) · 🔴 grande (quebrar antes).

---

## Trilha A — Hardening de Produção

Materializar o que hoje é simulado, sempre via **seams de adapter com lazy-import** — o
default offline continua funcionando sem dependências novas. Cada adapter real é um extra
opcional. Baseado em [`docs/10-arquitetura-producao.md`](docs/10-arquitetura-producao.md).

- [ ] `A1` 🟢 ADR + interface `KeyProvider`: `LocalKeyProvider` (default atual) e stub
  `VaultKeyProvider` (extra lazy). Chaves Ed25519 hoje vivem em memória/arquivo
  (`src/governance/signing/`). **Decisão arquitetural → ADR-010.**
- [ ] `A2` 🟢 Interface `AuditSink`: `JsonlAuditSink` (default atual em
  `src/governance/audit/`) e stub `KafkaAuditSink` (extra lazy).
- [ ] `A3` 🟡 Seam de identidade externa: `IdentityProvider` local (atual) e stub
  `SpiffeIdentityProvider` (`src/governance/identity/`).
- [ ] `A4` 🟡 Seam de isolamento de execução de tool (subprocess/gVisor) documentado +
  ponto de extensão no `src/governance/runtime/`.
- [ ] `A5` 🟢 Doc + seam para transporte mTLS entre componentes.

## Trilha B — Adapters reais de LLM

Endurecer a camada `src/governance/llm/` (materializa o
[`ADR-009`](docs/adr/ADR-009-neutralidade-de-provedor-llm.md)). Testes reais ficam **skip
por padrão** para não quebrar o CI offline.

- [ ] `B1` 🟢 Harness de teste de integração para adapters reais, **skip por padrão**
  (gated por env/API key presente).
- [ ] `B2` 🟢 Endurecer `AnthropicAdapter`: retry, timeout, mapeamento de erro e atributos
  `gen_ai.*` na telemetria.
- [ ] `B3` 🟢 Mesmo tratamento para `OpenAIAdapter`.
- [ ] `B4` 🟢 Teste de integração local do `OllamaAdapter`.
- [ ] `B5` 🟢 Config e validação do caminho Azure.
- [ ] `B6` 🟡 Suporte a streaming na interface `LlmProvider`, com governança preservada.

## Trilha C — Mais evals e testes

Ampliar `evals/scenarios/` e `tests/`. **Um ataque novo = um dia.**

- [ ] `C1` 🟢 Novo cenário adversarial: tool poisoning.
- [ ] `C1b` 🟢 Novo cenário adversarial: indirect prompt injection via memória.
- [ ] `C1c` 🟢 Novo cenário adversarial: replay A2A em condição de borda.
- [ ] `C2` 🟡 Fechar lacunas de cobertura nos módulos mais fracos (medir com `make test`).
- [ ] `C3` 🟢 Property-based tests para a verificação do hash chain
  (`src/governance/audit/`).
- [ ] `C4` 🟡 Eval dedicado para cada item do OWASP Agentic Top 10 ainda não coberto.

## Trilha D — Docs, ADRs e compliance

Atualizar `docs/` conforme as outras trilhas avançam.

- [ ] `D1` 🟢 ADR para cada decisão arquitetural das trilhas A/B (acompanha o PR).
- [ ] `D2` 🟡 Aprofundar mapeamento EU AI Act com artigos específicos
  (`docs/09-mapeamento-compliance.md`).
- [ ] `D3` 🟢 Novo runbook operacional em `runbooks/`.
- [ ] `D4` 🟢 Atualizar diagramas mermaid conforme novos seams surgem.

---

## Concluídos

- [x] `D0` Instalar o sistema de melhoria incremental: `ROADMAP.md`, `CHANGELOG.md` e o
  Fluxo de Melhoria Diária em `CONTRIBUTING.md`.
