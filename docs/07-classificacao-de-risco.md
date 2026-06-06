# 07: Classificação de Risco

## Níveis de risco

| Nível | Código | Critérios | Exemplos |
|-------|--------|-----------|---------|
| **Baixo** | `low` | Reversível, impacto limitado, somente leitura | `read_files`, `list_files`, `query_database` |
| **Médio** | `medium` | Potencial de impacto moderado, reversível | `write_files`, `send_notification`, `call_internal_api` |
| **Alto** | `high` | Impacto significativo, difícil de reverter | `send_email`, `execute_code`, `update_database` |
| **Crítico** | `critical` | Irreversível, impacto catastrófico potencial | `delete_files`, `wipe_database`, `drop_table` |

## Critérios de avaliação

Para classificar uma ferramenta, responda:

```
1. A ação é REVERSÍVEL?
   Não → eleva pelo menos para HIGH

2. Qual o RAIO DE IMPACTO?
   Usuário único → LOW/MEDIUM
   Time/sistema → MEDIUM/HIGH
   Toda a organização → HIGH/CRITICAL

3. A ação afeta DADOS SENSÍVEIS?
   Sim → eleva pelo menos para MEDIUM

4. A ação é DESTRUTIVA (remove dados permanentemente)?
   Sim → CRITICAL

5. A ação envolve COMUNICAÇÃO EXTERNA?
   Sim → pelo menos MEDIUM
```

## Matriz de ferramentas

| Ferramenta | Risco | Destrutiva | Reversível | Escopo |
|-----------|-------|------------|------------|--------|
| `read_files` | LOW | Não | N/A | `read:files` |
| `list_files` | LOW | Não | N/A | `read:files` |
| `query_database` | LOW | Não | N/A | `read:database` |
| `call_internal_api` (GET) | LOW | Não | N/A | `call:internal_api` |
| `write_files` | MEDIUM | Não | Sim | `write:files` |
| `send_notification` | MEDIUM | Não | Não | `send:notification` |
| `update_database` | MEDIUM | Não | Sim | `write:database` |
| `call_external_api` | MEDIUM | Não | Não | `call:external_api` |
| `send_email` | HIGH | Não | Não | `send:email` |
| `execute_code` | HIGH | Depende | Depende | `execute:code` |
| `read_secrets` | HIGH | Não | N/A | `read:secrets` |
| `delete_files` | CRITICAL | **Sim** | Não | `delete:files` |
| `wipe_database` | CRITICAL | **Sim** | Não | `delete:files` |
| `drop_table` | CRITICAL | **Sim** | Não | `write:database` |

## Risco do agente vs. risco da ação

O nível de risco pode ser especificado em dois níveis:

1. **Na ferramenta** (ToolDefinition.risk_level): valor padrão, reflete a ferramenta em si
2. **Na chamada** (GovernedAgentRuntime.execute(..., risk_level=HIGH)): sobrescreve o padrão

O runtime usa o valor mais alto entre os dois:

```python
# Ferramenta tem risco LOW, mas o contexto é de alto risco
result = runtime.execute(
    agent,
    "read_files",
    {"path": "/prod/secrets/"},
    risk_level=RiskLevel.HIGH,  # eleva o risco para este contexto específico
)
```

## Ajuste dinâmico de risco

Em sistemas mais avançados, o risco pode ser ajustado dinamicamente com base em:

- **Velocidade de chamadas**: muitas chamadas em pouco tempo → eleva risco
- **Padrões anômalos**: o agente está chamando ferramentas fora do seu padrão
- **Contexto**: o mesmo agente em `prod` tem risco mais alto que em `dev`
- **Hora do dia**: ações fora do horário comercial podem exigir aprovação extra

Esses ajustes não estão implementados neste repositório mas são acomodados pelo
runtime via o parâmetro `risk_level` opcional.
