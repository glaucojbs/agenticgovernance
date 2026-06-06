# ADR-001: Política como Código (YAML declarativo)

**Status:** Aceito  
**Data:** 2025-06-01  
**Autores:** Time de Plataforma de IA

---

## Contexto

Precisávamos de um mecanismo para definir o que agentes de IA têm permissão de
fazer. As alternativas consideradas foram:

1. **Hardcode no agente**: lógica de permissão embutida no código de cada agente
2. **Banco de dados de ACL**: tabelas de permissão consultadas em runtime
3. **Política declarativa em arquivos (YAML/JSON)**: arquivos versionados junto ao código
4. **Policy engine externo (OPA/Cedar)**: serviço separado de avaliação de política

## Decisão

Adotamos **políticas declarativas em YAML versionadas no repositório**, avaliadas
por um motor simples implementado em Python.

## Motivação

| Critério | Hardcode | ACL DB | YAML (escolhido) | OPA/Cedar |
|----------|---------|--------|-----------------|----------|
| Revisão via diff | Não | Não | **Sim** | **Sim** |
| Testável sem infra | Não | Não | **Sim** | Parcial |
| Curva de aprendizado | Baixa | Baixa | **Baixa** | Média |
| Velocidade de avaliação | Alta | Média | Alta | **Muito alta** |
| Expressividade | Baixa | Média | Média | **Alta** |
| Deploy sem mudança de código | Não | Sim | **Sim** | Sim |

O YAML declarativo oferece o melhor equilíbrio para este repositório de referência:
é legível por não-especialistas, testável em CI e não exige infraestrutura adicional.

## Consequências

**Positivas:**
- Toda mudança de política é um commit Git com autor, data e diff
- Fácil de testar em isolamento (`pytest tests/test_policy.py`)
- Não requer serviço externo rodando para funcionar

**Negativas / Limitações:**
- Expressividade limitada: sem joins, negação, recursão
- Não escalável acima de ~1.000 avaliações/segundo (sem cache)
- Mudanças de política requerem redeploy da aplicação (a menos que o motor
  recarregue arquivos em runtime via `PolicyEngine.reload()`)

## Ponto de extensão

O `PolicyEngine` foi projetado como uma interface substituível. Para migrar para
OPA, implementar um `OpaPolicyEngine` com a mesma assinatura de `evaluate()`.
Exemplos Rego estão em `policies/examples-rego/` como ponto de partida.
