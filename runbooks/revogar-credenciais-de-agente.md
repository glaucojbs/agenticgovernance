# Runbook — Revogação de Credenciais de Agente

**Versão:** 1.0  
**Audiência:** Time de operações, time de segurança

---

## Quando revogar

- Credencial de agente comprometida (ex.: token vazado em log ou repositório)
- Agente se comportando de forma anômala e precisa ser parado imediatamente
- Fim do ciclo de vida do agente (antes de deprecar no registry)
- Rotação periódica de credenciais (política de segurança)

---

## Tipos de revogação

### 1. Revogação da credencial (token)

O agente perde autenticação imediatamente. A próxima tentativa de execução
será bloqueada com "Credencial inválida ou expirada".

```python
from governance.identity.manager import IdentityManager

manager = IdentityManager()  # use a instância da aplicação
manager.revoke("agent-id", reason="credencial comprometida — token vazado em PR #123")
```

### 2. Revogação de escopo específico

Remove uma capacidade específica sem invalidar toda a autenticação.

```python
from governance.identity.models import AgentScope

manager.revoke_scope("agent-id", AgentScope.DELETE_FILES)
# O agente ainda pode autenticar e executar outras ferramentas
```

### 3. Renovação de credencial

Emite um novo token (invalida o anterior via substituição).

```python
new_cred = manager.renew_credential("agent-id", ttl_seconds=3600)
print(f"Novo token: {new_cred.token[:8]}...")
```

---

## Procedimento de emergência

### 1. Identifique o agente

```bash
# Se você tem o token comprometido, encontre o agente no audit log
python3 -c "
import json
with open('audit_logs/producao/audit.jsonl') as f:
    for line in f:
        event = json.loads(line)
        if event.get('agent_id'):
            print(event['agent_id'], event['agent_name'], event['timestamp'])
" | sort -u
```

### 2. Revogue a credencial

```python
manager.revoke("agent-id-comprometido", reason="emergência: [descrever]")
```

### 3. Verifique que a revogação funcionou

```python
identity = manager.get("agent-id-comprometido")
print("Autenticado:", identity.is_authenticated())       # deve ser False
print("Credencial revogada:", identity.credential.revoked)  # deve ser True
```

### 4. Deprece o agente no registry (se for o caso)

```python
from governance.registry.catalog import AgentRegistry

registry = AgentRegistry()  # use a instância da aplicação
registry.deprecate("agent-id-comprometido")
```

---

## Auditoria pós-revogação

Após a revogação, verifique o audit log para confirmar:

```python
from governance.audit.logger import AuditLogger

logger = AuditLogger("audit_logs/producao/audit.jsonl")
events = logger.get_events_for_agent("agent-id-comprometido")

# Procure por tentativas de acesso após a revogação
from governance.audit.logger import AuditEventType
denied_after = [
    e for e in events
    if e.event_type in (AuditEventType.ACTION_DENIED, AuditEventType.CREDENTIAL_REVOKED)
]
for e in denied_after:
    print(f"[{e.timestamp}] {e.event_type.value}: {e.details}")
```

---

## Prevenção

- **TTL curto**: configure `ttl_seconds=3600` (1h) ou menos em produção
- **Rotação periódica**: renove credenciais antes do vencimento via job agendado
- **Monitoramento**: alertas para credenciais a menos de 15 minutos do vencimento
- **Never log tokens**: garanta que tokens não aparecem em logs de aplicação
