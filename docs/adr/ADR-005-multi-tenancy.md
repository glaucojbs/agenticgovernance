# ADR-005: Arquitetura Multi-Tenant

**Status:** Aceito  
**Data:** 2026-06-04  
**Autores:** Time de Plataforma de IA

---

## Contexto

O repositório começou com um runtime único compartilhado. À medida que equipes
diferentes adotam a plataforma, surgiu a necessidade de **isolamento entre tenants**:
políticas diferentes, budgets independentes, audit logs separados e kill switches
que não afetam outras equipes.

## Decisão

Adotamos um modelo de **tenant por instância de componentes** com `TenantRuntime`
como facade de roteamento, implementado em `src/governance/tenancy/`.

## Modelo adotado

```
TenantRegistry
  ├-- Tenant(team-alpha)
  │     ├-- PolicyEngine(policies/alpha/)    ← políticas próprias
  │     ├-- BudgetGuard(config=alpha_budget) ← limites próprios
  │     ├-- AgentRegistry()                  ← agentes próprios
  │     ├-- AuditLogger(audit/alpha.jsonl)   ← log separado
  │     └-- ApprovalGate(.kill_switch_alpha) ← kill switch local
  └-- Tenant(team-beta)
        ├-- PolicyEngine(policies/beta/)
        └-- ...
```

**Garantia de isolamento:** `Tenant.execute()` verifica que o `agent_id` está
registrado **naquele tenant** antes de executar. Agentes de outro tenant são
bloqueados com erro explícito.

## Alternativas consideradas

| Abordagem | Vantagem | Desvantagem |
|-----------|----------|-------------|
| **Instâncias separadas por tenant** (escolhida) | Isolamento real; simples de raciocinar | Mais memória por tenant |
| Namespace por tenant em instância única | Menos memória | Risco de vazamento de contexto |
| RBAC dentro do PolicyEngine | Políticas granulares | Complexidade alta; não isola audit log |

## Consequências

**Positivas:**
- Cada tenant é completamente independente: falha de um não afeta outro
- Kill switch local: equipe A pode parar seus agentes sem afetar equipe B
- Kill switch global: operador da plataforma para todos simultaneamente
- Audit logs por tenant facilitam compliance e rastreabilidade

**Negativas / Limitações:**
- Em produção, cada tenant provavelmente precisará de processo separado
  (não apenas instâncias em memória) para isolamento de CPU/memória
- Políticas compartilhadas entre tenants requerem cópia manual por enquanto
  (em produção: bundle server OPA com herança de políticas)
