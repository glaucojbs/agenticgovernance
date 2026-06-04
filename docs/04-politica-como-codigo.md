# 04 — Política como Código

## Por que política como código?

Regras de negócio embutidas no código do agente são:
- Invisíveis para revisão independente
- Difíceis de testar em isolamento
- Impossíveis de auditar via diff
- Duplicadas entre agentes diferentes

Política como código externaliza essas regras em arquivos declarativos versionados,
revisáveis e testáveis separadamente do código dos agentes.

## Estrutura de um arquivo de política

```yaml
# policies/meu-agente.yaml
rules:
  - name: deny-destruição-produção     # nome único e descritivo
    decision: DENY                      # ALLOW | DENY | REQUIRE_APPROVAL
    tools:                              # ferramentas a que a regra se aplica
      - delete_files
      - drop_table
    environments: ["prod", "staging"]   # ambientes (["*"] = todos)
    risk_levels: ["*"]                  # níveis de risco (["*"] = todos)
    scopes_required: []                 # escopos que o agente DEVE ter
    conditions:                         # condições adicionais nos parâmetros
      path:
        not_in: ["/tmp", "/var/tmp"]
    reason: "Exclusão proibida em prod/staging fora de /tmp"
```

## Campos disponíveis

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `name` | string | — | Identificador único da regra |
| `decision` | enum | — | `ALLOW`, `DENY` ou `REQUIRE_APPROVAL` |
| `tools` | list | `["*"]` | Ferramentas que ativam a regra |
| `environments` | list | `["*"]` | Ambientes que ativam a regra |
| `risk_levels` | list | `["*"]` | Níveis de risco que ativam a regra |
| `scopes_required` | list | `[]` | Escopos que o agente deve possuir |
| `conditions` | dict | `{}` | Condições nos parâmetros da ação |
| `reason` | string | — | Mensagem exibida quando a regra bate |

## Condições de parâmetros

```yaml
conditions:
  # Valor numérico com teto
  max_rows:
    max: 10000

  # Valor numérico com piso
  page_size:
    min: 1

  # Valor não pode estar na lista
  environment:
    not_in: ["prod", "staging"]

  # Valor deve estar na lista
  operation_type:
    in: ["read", "list"]
```

## Ordem de avaliação (precedência)

```
DENY → REQUIRE_APPROVAL → ALLOW → default-deny
```

O motor itera as regras em ordem de arquivo (alfabético) e dentro de cada arquivo
na ordem declarada. A **primeira regra DENY que bate** encerra a avaliação imediatamente.

## Exemplos de políticas

### 1. Política de leitura apenas

```yaml
rules:
  - name: deny-writes
    decision: DENY
    tools: ["write_files", "update_database", "send_email"]
    environments: ["*"]
    reason: "Agente de leitura não pode modificar dados"

  - name: allow-reads
    decision: ALLOW
    tools: ["read_files", "list_files", "query_database"]
    scopes_required: ["read:files"]
    environments: ["*"]
    risk_levels: ["low", "medium"]
    reason: "Leitura permitida com escopo correto"
```

### 2. Política de aprovação em produção

```yaml
rules:
  - name: require-approval-prod-writes
    decision: REQUIRE_APPROVAL
    tools: ["write_files", "update_database"]
    scopes_required: ["write:files"]
    environments: ["prod"]
    reason: "Escrita em produção requer aprovação"

  - name: allow-writes-non-prod
    decision: ALLOW
    tools: ["write_files"]
    scopes_required: ["write:files"]
    environments: ["dev", "staging"]
    risk_levels: ["low", "medium"]
    reason: "Escrita permitida fora de produção"
```

## Alternativas de mercado (OPA e Cedar)

O motor YAML deste repositório é suficiente para a maioria dos casos de uso.
Para ambientes de maior escala, considere:

| Quando usar OPA/Rego | Quando usar Cedar |
|---------------------|------------------|
| Políticas com lógica complexa (joins, negação) | Ecossistema AWS |
| Integração com Kubernetes (Gatekeeper) | Verificação formal de políticas |
| >1.000 avaliações/segundo | Velocidade com segurança de tipos |
| Compartilhamento de políticas entre sistemas | `cedar validate` antes de deploy |

Exemplos Rego estão em `policies/examples-rego/`.
Veja também: [ADR-001](adr/ADR-001-politica-como-codigo.md)
