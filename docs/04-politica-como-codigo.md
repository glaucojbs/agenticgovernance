# 04: Política como Código

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
| `name` | string | N/A | Identificador único da regra |
| `decision` | enum | N/A | `ALLOW`, `DENY` ou `REQUIRE_APPROVAL` |
| `tools` | list | `["*"]` | Ferramentas que ativam a regra |
| `environments` | list | `["*"]` | Ambientes que ativam a regra |
| `risk_levels` | list | `["*"]` | Níveis de risco que ativam a regra |
| `scopes_required` | list | `[]` | Escopos que o agente deve possuir |
| `conditions` | dict | `{}` | Condições nos parâmetros da ação |
| `allowed_utc_hours` | list[int] | `[]` | Horas UTC em que a regra se aplica (0-23). Lista vazia = sem restrição. |
| `allowed_weekdays` | list[int] | `[]` | Dias da semana (0=seg…6=dom). Lista vazia = sem restrição. |
| `reason` | string | N/A | Mensagem exibida quando a regra bate |

## Condições temporais

Úteis para restringir ações a janelas de tempo: ex.: operações de manutenção
só durante o horário comercial, ou bloquear deploys em fins de semana:

```yaml
rules:
  # Só permite durante o horário comercial UTC (9h-17h, seg-sex)
  - name: allow-maintenance-business-hours
    decision: ALLOW
    tools: ["run_migration"]
    scopes_required: ["write:database"]
    environments: ["prod"]
    allowed_utc_hours: [9, 10, 11, 12, 13, 14, 15, 16]
    allowed_weekdays: [0, 1, 2, 3, 4]   # segunda a sexta
    reason: "Migrações permitidas apenas durante o horário comercial"

  # Fora do horário acima, a regra não bate → cai no default-deny
```

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

## Policy Dry-run: testar mudanças antes de aplicar

Antes de fazer merge de uma PR que altera políticas, compare as decisões atual × proposta:

```python
from governance.policy.dryrun import PolicyDryRun
from governance.policy.engine import ActionRequest, RiskLevel
from governance.identity.models import AgentEnvironment, AgentScope

dry_run = PolicyDryRun.from_dirs(
    current_dir="policies/",
    proposed_dir="policies-proposed/",
)

# Batch de requests representativos do seu sistema
requests = [
    ActionRequest(
        agent_id="test", agent_name="Test",
        tool_name="query_database",
        environment=AgentEnvironment.PROD,
        scopes=[AgentScope.READ_DATABASE],
        risk_level=RiskLevel.LOW,
        parameters={},
    ),
    # ... outros requests
]

report = dry_run.compare(requests)
print(report.render())
# ↑ Promoções (DENY→ALLOW): exigem revisão de segurança
# ↓ Restrições (ALLOW→DENY): podem quebrar agentes em produção
```

Via CLI:
```bash
governance policy dryrun policies/ policies-proposed/
```

O CI executa dry-run automaticamente em PRs que alteram `policies/*.yaml`.

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

### 3. Avaliação via CLI (sem escrever código)

```bash
# Simula uma decisão de política diretamente no terminal
governance policy eval \
  --tool-name query_database \
  --environment prod \
  --risk-level low \
  --scopes "read:database"

#   ✓  DECISÃO: ALLOW
#      Motivo  : Consultas de leitura ao banco permitidas para agentes com escopo 'read:database'.
#      Regra   : allow-read-database (example-readonly-agent.yaml)
```

## Alternativas de mercado (OPA e Cedar)

O motor YAML deste repositório é suficiente para a maioria dos casos de uso.
O `OpaPolicyEngine` já está implementado com fallback automático:

```python
from governance.policy.opa_client import OpaPolicyEngine
from governance.policy.engine import PolicyEngine

engine = OpaPolicyEngine(
    opa_url="http://localhost:8181",        # OPA server (docker compose up)
    fallback=PolicyEngine("policies/"),     # fallback automático se OPA offline
    timeout_seconds=0.5,
)
```

Para ambientes de maior escala, considere migrar inteiramente para OPA:

| Quando usar OPA/Rego | Quando usar Cedar |
|---------------------|------------------|
| Políticas com lógica complexa (joins, negação) | Ecossistema AWS |
| Integração com Kubernetes (Gatekeeper) | Verificação formal de políticas |
| >1.000 avaliações/segundo | Velocidade com segurança de tipos |
| Compartilhamento de políticas entre sistemas | `cedar validate` antes de deploy |

Exemplos Rego executáveis estão em `docker/opa/policies/` (carregados pelo OPA server do Compose)
e exemplos ilustrativos em `policies/examples-rego/`.
Veja também: [ADR-001](adr/ADR-001-politica-como-codigo.md)
