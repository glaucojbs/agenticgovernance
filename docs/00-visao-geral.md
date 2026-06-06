# 00 — Visão Geral

## O problema

Agentes de IA autônomos estão sendo implantados em ambientes de produção onde podem:

- Ler e modificar dados sensíveis
- Enviar comunicações em nome da organização
- Chamar APIs externas e internas
- Executar código arbitrário
- Criar outros agentes (sub-agentes)

Sem uma camada de governança, **cada agente é uma superfície de ataque independente**:
nenhuma visibilidade centralizada, nenhum mecanismo de revogação, nenhum controle de impacto.

## O que este repositório oferece

Um **conjunto de componentes de governança executáveis** que qualquer equipe pode clonar,
adaptar e colocar em produção. Os componentes são ortogonais e composáveis — adote apenas
o que precisar.

```
Componente          O que ele resolve
──────────────────  ─────────────────────────────────────────────────────────
identity            Quem é este agente? Ele está autenticado?
policy              O que este agente tem permissão de fazer?
                    (motor YAML + OPA client + condições temporais + dry-run)
audit               O que este agente fez? (JSONL append-only + hash chain)
signing             As entradas do log foram adulteradas? (Ed25519 por entrada)
budget              Quanto este agente gastou? Ele está dentro dos limites?
approval            Esta ação precisa de aprovação humana? (HITL + M-de-N)
registry            Este agente foi avaliado e aprovado para este ambiente?
runtime             Ponto único de execução — orquestra todos os controles.
                    (GovernanceConfig para injeção limpa de capacidades)
telemetry           O que está acontecendo agora? (OTEL traces + métricas)
anomaly             Este padrão de comportamento é suspeito? (regras em tempo real)
masking             Dados pessoais estão sendo gravados no log? (PII redaction)
circuit_breaker     Uma ferramenta com falhas está cascateando? (CLOSED/OPEN/HALF_OPEN)
vault               Como gerenciar segredos com TTL e rotação? (padrão Vault/KMS)
forensics           O que exatamente aconteceu durante o incidente? (IncidentReplayer)
compliance          Quais evidências apresentar ao auditor? (NIST/ISO/EU AI Act/OWASP)
tenancy             Múltiplas equipes na mesma plataforma com isolamento total.
cli                 Como operar o sistema sem escrever código? (governance kill-switch, etc.)
```

## Público-alvo

- **Times de plataforma de IA** que precisam de uma base para governança de agentes
- **Arquitetos de segurança** que avaliam riscos de sistemas agênticos
- **Times de compliance** que precisam mapear controles técnicos a frameworks regulatórios
- **Engenheiros** que estão migrando de agentes "livres" para agentes governados
- **Times de operações** que precisam operar e responder a incidentes com agentes

## Índice da documentação

| Documento | Conteúdo |
|-----------|---------|
| [01-arquitetura](01-arquitetura.md) | Control plane vs. data plane, diagrama completo, componentes |
| [02-modelo-de-governanca](02-modelo-de-governanca.md) | Princípios, papéis (RACI), fluxo de decisão, ameaças |
| [03-identidade-e-acesso](03-identidade-e-acesso.md) | Identidade, escopos, delegação, credenciais |
| [04-politica-como-codigo](04-politica-como-codigo.md) | Motor YAML, condições temporais, dry-run, OPA/Cedar |
| [05-observabilidade-e-auditoria](05-observabilidade-e-auditoria.md) | Hash chain, Ed25519, OTEL, PII masking, forensics, CLI |
| [06-supervisao-humana](06-supervisao-humana.md) | HITL, aprovação M-de-N, kill switch local e global |
| [07-classificacao-de-risco](07-classificacao-de-risco.md) | Níveis de risco, critérios, matriz de ferramentas |
| [08-ciclo-de-vida](08-ciclo-de-vida.md) | Registro, eval gate, promoção, compliance reporter |
| [09-mapeamento-compliance](09-mapeamento-compliance.md) | NIST AI RMF, ISO 42001, EU AI Act, OWASP LLM/Agentic |
| [10-arquitetura-producao](10-arquitetura-producao.md) | Stack big tech: SPIFFE, Kafka, Vault/KMS, gVisor, mTLS |
| [adr/](adr/) | Architecture Decision Records (ADR-001 a ADR-009) |
