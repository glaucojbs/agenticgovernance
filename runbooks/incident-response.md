# Runbook — Resposta a Incidentes com Agentes de IA

**Versão:** 1.0  
**Audiência:** Time de operações, SREs, time de segurança

---

## Classificação de severidade

| Severidade | Critérios | Tempo de resposta |
|-----------|-----------|------------------|
| **P0** | Agente executando ações destrutivas / dados comprometidos | Imediato (< 5 min) |
| **P1** | Comportamento anômalo detectado / escopo excedido | < 15 minutos |
| **P2** | Orçamento esgotado / aprovações repetidas negadas | < 1 hora |
| **P3** | Anomalias na trilha de auditoria / alertas de monitoramento | < 4 horas |

---

## Procedimento P0 — Contenção imediata

### Passo 1: Ativar o kill switch

```bash
# Acesso direto ao servidor (mais rápido)
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | P0: [descrever o incidente]" > .kill_switch

# Via código Python (se o servidor estiver acessível)
from governance.approval.gate import ApprovalGate
gate = ApprovalGate()
gate.activate_kill_switch("P0: comportamento destrutivo detectado")
```

Veja o runbook específico: [kill-switch.md](kill-switch.md)

### Passo 2: Revogar credenciais do agente suspeito

```bash
# Via código Python
from governance.identity.manager import IdentityManager
manager = IdentityManager()  # use a instância da aplicação
manager.revoke("agent-id-suspeito", reason="P0: incidente de segurança")
```

Veja o runbook específico: [revogar-credenciais-de-agente.md](revogar-credenciais-de-agente.md)

### Passo 3: Preservar evidências

```bash
# Copiar o audit log ANTES de qualquer limpeza
cp audit_logs/producao/audit.jsonl /tmp/incident_$(date +%Y%m%d_%H%M%S).jsonl

# Verificar integridade do log
python3 -c "
from governance.audit.logger import AuditLogger
logger = AuditLogger('audit_logs/producao/audit.jsonl')
result = logger.verify_chain()
print(f'Chain válida: {result.valid}, entradas: {result.total_entries}')
if not result.valid:
    print(f'Adulteração detectada na entrada #{result.first_broken_at}')
    print(f'Detalhe: {result.error}')
"
```

---

## Análise pós-incidente

### Replay dos eventos do agente suspeito

```python
from governance.audit.logger import AuditLogger

logger = AuditLogger("audit_logs/producao/audit.jsonl")
events = logger.get_events_for_agent("agent-id-suspeito")

for event in events:
    print(f"[{event.timestamp}] {event.event_type.value}")
    print(f"  Ferramenta: {event.tool_name}")
    print(f"  Detalhes: {event.details}")
    print()
```

### Verificação de integridade da cadeia

```python
result = logger.verify_chain()
if not result.valid:
    print(f"ALERTA: cadeia adulterada!")
    print(f"Primeira entrada comprometida: #{result.first_broken_at}")
```

---

## Checklist pós-incidente

- [ ] Kill switch ativado e ações do agente cessaram
- [ ] Credenciais revogadas (log de auditoria confirma `credential_revoked`)
- [ ] Audit log preservado em local seguro
- [ ] Integridade do log verificada (`verify_chain()` passou)
- [ ] Escopo do incidente mapeado (quais ferramentas foram chamadas, com que parâmetros)
- [ ] Post-mortem agendado em até 48h
- [ ] Política atualizada para prevenir recorrência
- [ ] Kill switch desativado somente após confirmação de contenção

---

## Comunicação

| Quem notificar | Quando | Canal |
|---------------|--------|-------|
| Dono do agente (AgentIdentity.owner) | Imediatamente | E-mail/Slack direto |
| Time de segurança | P0/P1: imediatamente | Canal de incidentes |
| Management | P0: < 30 minutos | Briefing executivo |
| Usuários afetados | Após contenção | Comunicado formal |
