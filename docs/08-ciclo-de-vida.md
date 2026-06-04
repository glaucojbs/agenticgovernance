# 08 — Ciclo de Vida de Agentes

## Estados de um agente

```mermaid
stateDiagram-v2
    [*] --> registered : AgentRegistry.register()
    registered --> approved : AgentRegistry.approve()\n[após eval gate]
    approved --> deprecated : AgentRegistry.deprecate()
    deprecated --> [*]
    registered --> deprecated : AgentRegistry.deprecate()

    note right of registered
        Pode operar em dev/staging
        Bloqueado em prod
    end note

    note right of approved
        Pode operar em todos os ambientes
        Passou pelo eval gate
    end note

    note right of deprecated
        Não pode ser instanciado
        em nenhum ambiente
    end note
```

## Fluxo de promoção para produção

```mermaid
flowchart TD
    DEV["Desenvolvimento\n(agente em dev)"] --> CODE["Code Review\n(PR aprovado)"]
    CODE --> UNIT["Testes Unitários\n(pytest — 124 testes)"]
    UNIT --> DRYRUN["Policy Dry-run\n(governance policy dryrun)"]
    DRYRUN --> |"Restrições detectadas"| REVIEW_POL["Revisar impacto\nnos agentes existentes"]
    REVIEW_POL --> DRYRUN
    DRYRUN --> EVAL["Eval Gate\n(make eval — 15 cenários)"]
    EVAL --> |"Exit code ≠ 0"| FAIL["❌ Bloqueado\nBarreira não segurou"]
    EVAL --> |"Exit code = 0"| REGISTER["AgentRegistry.register()"]
    REGISTER --> STAGING["Testes em Staging\n(smoke tests)"]
    STAGING --> SEC_REVIEW["Revisão de Segurança\n(threat model + STRIDE)"]
    SEC_REVIEW --> APPROVE["AgentRegistry.approve()\n+ eval_report"]
    APPROVE --> PROD["✅ Produção"]
```

## O eval gate como portão de qualidade

O eval gate (`make eval` / `evals/run_evals.py`) é a linha de defesa que valida
**automaticamente** que todas as barreiras de governança estão funcionando antes
de qualquer promoção.

### O que o eval gate verifica

| Categoria | Cenários | Barreira testada |
|-----------|----------|-----------------|
| A — Ferramentas destrutivas | A1, A2 | `policy/deny-delete-always` |
| B — Escalada de privilégio | B1, B2 | `identity/DelegationChain` |
| C — Burla de escopo | C1, C2 | `policy/default-deny`, `registry` |
| D — Orçamento | D1 | `budget/BudgetGuard` |
| E — Kill switch | E1, E2 | `approval/KillSwitch` |
| F — Ciclo de vida | F1, F2 | `registry/AgentStatus` |
| G — Credencial | G1, G2 | `identity/AgentCredential` |
| H — Default-deny | H1, H2 | `policy/default-deny`, `approval` |

### Regressão de governança

Ao introduzir uma nova política ou modificar o runtime, o eval gate detecta
imediatamente se alguma barreira foi quebrada — análogo a um teste de regressão,
mas para propriedades de segurança.

## Versionamento de agentes

Cada `AgentRecord` carrega um campo `version` (semver). Ao criar uma nova versão:

```python
# Registra a nova versão com ID diferente
new_agent = AgentRecord(
    agent_id="data-analyst-v2",
    name="DataAnalystAgent",
    version="2.0.0",
    owner="alice@empresa.com",
)
registry.register(new_agent)
# Promove v2 após eval
registry.approve("data-analyst-v2", eval_report="eval-2025-06-v2")
# Depreca v1
registry.deprecate("data-analyst-v1")
```

## Gerenciamento de ciclo de vida via CLI

```bash
# Verificar agentes no registry (via script Python — CLI não expõe listing ainda)
python -c "
from governance.registry.catalog import AgentRegistry
reg = AgentRegistry()
for a in reg.list_agents():
    print(a.agent_id, a.status.value, a.version)
"

# Audit trail de lifecycle
governance audit replay audit_logs/prod/audit.jsonl | grep agent_registered
```

## Auditoria do ciclo de vida

Eventos de ciclo de vida também são registrados na trilha de auditoria:
`agent_registered`, `credential_issued`, `credential_revoked`.

Em produção, registre também `approval` e `deprecation` como eventos auditados
para rastreabilidade completa de quem fez o quê e quando.

## Geração de evidências de compliance

Ao final de cada período de auditoria (trimestral, anual), gere o relatório de
evidências automaticamente a partir do audit log:

```python
from governance.compliance.reporter import ComplianceReporter

reporter = ComplianceReporter("audit_logs/prod/audit.jsonl")
evidence = reporter.generate()
print(evidence.render())

# Exporta para o auditor
evidence_json = evidence.to_json()
Path("compliance_evidence_Q2_2025.json").write_text(evidence_json)
```

Via CLI:
```bash
governance report compliance audit_logs/prod/audit.jsonl \
  --output compliance_evidence_Q2_2025.json
```

O relatório mapeia automaticamente cada tipo de evento para controles do
NIST AI RMF, ISO/IEC 42001, EU AI Act e OWASP LLM/Agentic Top 10.
Veja [`docs/09-mapeamento-compliance.md`](09-mapeamento-compliance.md) para o mapeamento completo.
