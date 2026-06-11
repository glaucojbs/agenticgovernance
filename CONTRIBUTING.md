# Guia de Contribuição

Obrigado por contribuir com este repositório de referência!

## Como contribuir

1. **Fork** o repositório e crie uma branch descritiva: `feat/nome-da-funcionalidade` ou `fix/descricao-do-bug`.
2. Siga as convenções: **código e identificadores em inglês**, **documentação em pt-BR**.
3. Antes de abrir um PR:
   - `make lint` deve passar sem erros.
   - `make test` deve passar com cobertura significativa para código novo.
   - `make eval` deve passar (barreiras de governança não podem regredir).
4. Inclua um ADR em `docs/adr/` se sua mudança introduz uma decisão arquitetural relevante.

## Fluxo de Melhoria Diária

A evolução deste repositório acontece em **incrementos pequenos e diários** (um PR por dia),
guiados pelo [`ROADMAP.md`](ROADMAP.md). O modo é **híbrido**: um agente propõe, um humano
aprova.

1. **Selecionar** — ler o `ROADMAP.md` e pegar o próximo item desbloqueado de maior
   prioridade.
2. **Propor** — apresentar um resumo curto: qual item, abordagem, arquivos afetados e se há
   decisão arquitetural (ADR). **Parar e aguardar aprovação humana.**
3. **Aprovar** — o humano confirma, ajusta o escopo ou troca de item.
4. **Implementar** — uma slice pequena; rodar os gates (`make lint` / `make test` /
   `make eval`).
5. **Registrar** — marcar o item no `ROADMAP.md` (`- [ ]` → `- [x]`), adicionar uma linha ao
   `CHANGELOG.md` e incluir o ADR se aplicável.
6. **PR** — abrir um PR `feat/...` ou `fix/...` para revisão e merge.

### Definição de Pronto de um incremento diário

- `make lint` passa sem erros.
- `make test` passa com cobertura para o código novo.
- `make eval` passa (sem regressão de governança).
- ADR adicionado em `docs/adr/` se houve decisão arquitetural.
- `CHANGELOG.md` atualizado e item marcado no `ROADMAP.md`.
- Branch `feat/...` ou `fix/...` e PR aberto.
- **Neutralidade preservada**: integrações reais entram por adapter com lazy-import, nunca
  como import direto no domínio (ver [`AGENTS.md`](AGENTS.md)).

## Convenções de código

- Python 3.11+, type hints em todo o `src/`.
- Use `pydantic` para modelos de dados.
- Sem frameworks pesados de agente: o objetivo é manter o código legível e didático.
- Comentários apenas quando a intenção de governança não for óbvia pelo código.

## O que NÃO commitar

- Segredos, chaves de API, tokens: use `.env.example` com placeholders.
- Arquivos `.env` reais.
- Logs de auditoria gerados em `audit_logs/`.
- O arquivo `.kill_switch`.

## Padrão de commits

```
tipo(escopo): descrição curta em inglês

Exemplos:
feat(policy): add environment-scoped conditions to YAML engine
fix(audit): correct hash chain verification for empty log
docs(adr): add ADR-004 for rate-limit strategy
test(budget): add edge cases for token overflow
```
