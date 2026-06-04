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
adaptar e colocar em produção. Os componentes são ortogonais e composáveis — você pode
adotar apenas o que precisar.

```
Componente              O que ele resolve
─────────────────────   ────────────────────────────────────────────────
identity                Quem é este agente? Ele está autenticado?
policy                  O que este agente tem permissão de fazer?
audit                   O que este agente fez? (à prova de adulteração)
budget                  Quanto este agente gastou? Ele está dentro dos limites?
approval                Esta ação precisa de aprovação humana?
registry                Este agente foi avaliado e aprovado para este ambiente?
runtime                 Ponto único de execução — orquestra todos os controles.
```

## Público-alvo

- **Times de plataforma de IA** que precisam de uma base para governança de agentes
- **Arquitetos de segurança** que avaliam riscos de sistemas agênticos
- **Times de compliance** que precisam mapear controles técnicos a frameworks regulatórios
- **Engenheiros** que estão migrando de agentes "livres" para agentes governados

## Índice da documentação

| Documento | Conteúdo |
|-----------|---------|
| [01-arquitetura](01-arquitetura.md) | Control plane vs. data plane, diagrama completo |
| [02-modelo-de-governanca](02-modelo-de-governanca.md) | Princípios, papéis (RACI), fluxo de decisão |
| [03-identidade-e-acesso](03-identidade-e-acesso.md) | Identidade, escopos, delegação, credenciais |
| [04-politica-como-codigo](04-politica-como-codigo.md) | Motor de política, YAML, exemplos, Rego/OPA |
| [05-observabilidade-e-auditoria](05-observabilidade-e-auditoria.md) | Hash chain, JSONL, replay, verificação |
| [06-supervisao-humana](06-supervisao-humana.md) | HITL, fluxo de aprovação, kill switch |
| [07-classificacao-de-risco](07-classificacao-de-risco.md) | Níveis de risco, critérios, tabela de ferramentas |
| [08-ciclo-de-vida](08-ciclo-de-vida.md) | Registro, avaliação, promoção, deprecação |
| [09-mapeamento-compliance](09-mapeamento-compliance.md) | NIST AI RMF, ISO 42001, EU AI Act, OWASP |
| [adr/](adr/) | Architecture Decision Records |
