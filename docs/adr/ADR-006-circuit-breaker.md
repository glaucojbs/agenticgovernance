# ADR-006 — Circuit Breaker por Ferramenta

**Status:** Aceito  
**Data:** 2026-06-04  
**Autores:** Time de Plataforma de IA

---

## Contexto

Ferramentas externas (APIs, bancos de dados) podem falhar de forma intermitente.
Sem proteção, cada falha resulta em timeout completo antes de retornar erro,
e múltiplos agentes tentando simultaneamente podem saturar um serviço já degradado.

## Decisão

Adotamos **circuit breaker por ferramenta** com os estados clássicos
CLOSED / OPEN / HALF_OPEN, implementado em `src/governance/circuit_breaker/`.

## Estados

```
CLOSED → falhas são contadas; sistema opera normalmente
OPEN   → após N falhas consecutivas; retorna erro imediatamente (fail-fast)
HALF_OPEN → após timeout; uma chamada de prova decide se fecha ou reabre
```

## Motivação

O padrão circuit breaker é preferível a timeouts simples porque:

1. **Fail-fast**: não espera o timeout para retornar erro ao agente
2. **Recovery automático**: testa periodicamente se o serviço se recuperou
3. **Blast radius**: impede que um serviço degradado seja saturado por múltiplos agentes
4. **Auditável**: cada transição de estado é registrada em `CircuitBreaker.events`

## Configuração padrão

| Parâmetro | Padrão | Razão |
|-----------|--------|-------|
| `failure_threshold` | 5 falhas | Tolerância a erros transitórios |
| `success_threshold` | 2 sucessos em HALF_OPEN | Evita fechar o circuito prematuramente |
| `timeout_seconds` | 60s | Tempo mínimo antes de tentar novamente |

## Consequências

**Positivas:**
- Experiência de falha mais rápida para os agentes
- Proteção de serviços degradados
- Observabilidade: `status()` retorna estado atual e contagem de transições

**Negativas / Limitações:**
- Falhas causadas por problemas nos parâmetros (não na ferramenta) também contam
- Estado em memória — reiniciar o processo reseta todos os breakers
- Em produção: persistir estado em Redis para durabilidade entre deploys

## Integração com GovernanceConfig

```python
from governance.circuit_breaker.breaker import CircuitBreakerRegistry
from governance.runtime.config import GovernanceConfig

cb_registry = CircuitBreakerRegistry(
    default_failure_threshold=5,
    default_timeout_seconds=60.0,
)
# Configuração específica para ferramentas críticas
cb_registry.register(CircuitBreaker("wipe_database", failure_threshold=1))

config = GovernanceConfig(circuit_breakers=cb_registry)
```
