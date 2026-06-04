# Runbook — Resposta a Incidentes com Agentes de IA

**Versão:** 1.1  
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
# Via CLI (método preferido — não requer Python)
governance kill-switch enable "P0: [descrever o incidente]"

# Acesso direto ao servidor (mais rápido ainda, sem CLI)
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | P0: [descrever o incidente]" > .kill_switch

# Via código Python
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

# Verificar integridade via CLI
governance audit verify audit_logs/producao/audit.jsonl

# Verificar assinaturas Ed25519 (se usando SignedAuditLogger)
python3 -c "
from governance.signing.signer import SignedAuditLogger, AuditSigner
logger = SignedAuditLogger.__new__(SignedAuditLogger)
logger._log_path = __import__('pathlib').Path('audit_logs/producao/audit.jsonl')
pub_key = open('keys/audit_public.pem').read()
result = logger.verify_signatures(pub_key)
print('Assinaturas válidas:', result['valid'], '/', result['total'])
if result['invalid_entries']:
    print('Entradas com problema:', result['invalid_entries'])
"
```

---

## Análise pós-incidente

### Reconstrução forense via CLI (método mais rápido)

```bash
# Reconstruir timeline completa do agente suspeito
governance forensics audit_logs/producao/audit.jsonl --agents agent-id-suspeito

# Ver estatísticas do log
governance audit stats audit_logs/producao/audit.jsonl

# Replay filtrado por agente
governance audit replay audit_logs/producao/audit.jsonl --agent agent-id-suspeito
```

### Reconstrução forense via Python (mais controle)

```python
from governance.forensics.replayer import IncidentReplayer

replayer = IncidentReplayer("audit_logs/producao/audit.jsonl")

# Verifica integridade antes de analisar
ok, msg = replayer.verify_integrity()
print(f"Integridade: {msg}")

# Reconstrói timeline
timeline = replayer.replay(agent_ids=["agent-id-suspeito"])
print(timeline.render_timeline())

# Resumo de impacto
summary = replayer.agent_activity_summary("agent-id-suspeito")
print(f"Taxa de negação: {summary['deny_rate']:.0%}")
print(f"Ferramentas executadas: {summary['tools_executed']}")
print(f"Ferramentas tentadas (negadas): {summary['tools_denied']}")
```

### Geração de evidências para relatório

```bash
# Gera relatório de compliance automático (para o post-mortem)
governance report compliance audit_logs/producao/audit.jsonl \
  --output incident_evidence_$(date +%Y%m%d).json
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
