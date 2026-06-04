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

## Convenções de código

- Python 3.11+, type hints em todo o `src/`.
- Use `pydantic` para modelos de dados.
- Sem frameworks pesados de agente — o objetivo é manter o código legível e didático.
- Comentários apenas quando a intenção de governança não for óbvia pelo código.

## O que NÃO commitar

- Segredos, chaves de API, tokens — use `.env.example` com placeholders.
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
