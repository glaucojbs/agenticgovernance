# ADR-007: PII Masking no Audit Log

**Status:** Aceito  
**Data:** 2026-06-04  
**Autores:** Time de Plataforma de IA

---

## Contexto

Agentes frequentemente recebem parâmetros que contêm dados pessoais :
e-mails de destinatários, CPFs em queries de banco, tokens de autenticação.
Gravar esses dados em texto claro no audit log viola LGPD/GDPR e cria
um vetor de exposição desnecessário.

## Decisão

Adotamos **PII masking na camada do runtime**, aplicado **antes** de qualquer
auditoria, implementado em `src/governance/masking/masker.py`.

## Por que no runtime (não no logger)?

| Abordagem | Vantagem | Desvantagem |
|-----------|----------|-------------|
| **No runtime antes do log** (escolhida) | PII nunca chega ao log | Runtime precisa conhecer as regras |
| No logger durante escrita | Logger desacoplado | Runtime pode logar PII temporariamente |
| Pós-processamento do log | Não muda o código | PII pode ser lido antes da limpeza |
| Tokenização via Vault Transit | Reversível | Dependência de infra; latência |

O masking no runtime garante que **nenhuma linha do JSONL já contém PII**,
eliminando a necessidade de processos de limpeza retroativa.

## Padrões built-in

`PIIMasker.with_defaults()` cobre os casos mais comuns:
- E-mail (`user@domain.com` → `[EMAIL]`)
- CPF (`123.456.789-00` → `[CPF]`)
- CNPJ (`12.345.678/0001-90` → `[CNPJ]`)
- Telefone BR (`(11) 9 1234-5678` → `[PHONE_BR]`)
- Cartão de crédito (`4111 1111 1111 1111` → `[CREDIT_CARD]`)
- JWT (`eyJ...` → `[JWT_TOKEN]`)
- API Key (`sk-abc123...` → `[API_KEY]`)
- IP (`192.168.1.1` → `[IP_ADDRESS]`)

## Limitações conhecidas

- **Não é reversível**: dados mascarados não podem ser recuperados do log.
  Use com cuidado em contextos de debugging onde o dado pode ser necessário.
- **Falsos positivos**: regex de cartão de crédito pode mascarar números longos
  legítimos. Ajustar padrão se necessário.
- **Masking parcial não é substituto de criptografia** em dados muito sensíveis.

## Extensão para domínios específicos

```python
masker = PIIMasker.with_defaults()
# Adiciona número de conta bancária (padrão específico do negócio)
masker.add_rule(r"\bAG\d{4}-\d{6}\b", "[ACCOUNT]", "bank_account")
```

## Consequências

**Positivas:**
- Compliance LGPD/GDPR: dados pessoais não aparecem em texto claro nos logs
- Simplifica auditorias: auditores não precisam de acesso a dados pessoais para verificar controles
- Reduz risco de exposição em caso de vazamento do arquivo de log

**Negativas / Limitações:**
- Debugging de problemas com dados pessoais fica mais difícil
- Regex pode ter falsos positivos; requer calibração por domínio
- Não protege dados em trânsito (use TLS) nem em repouso além do log (use encryption at rest)
