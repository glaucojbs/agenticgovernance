# Runbook — Kill Switch Global

**Versão:** 1.0  
**Audiência:** Time de operações, SREs

---

## O que é o kill switch

O kill switch é um **mecanismo de parada de emergência** que bloqueia toda execução
de agentes de IA imediatamente. É implementado como um arquivo em disco:
se o arquivo `.kill_switch` existe, todos os agentes são bloqueados.

O design é intencionalmente simples: qualquer operador com acesso ao servidor
pode ativar o kill switch sem código, sem senha adicional, sem aprovação de terceiros.

---

## Quando usar

- Comportamento de agente destrutivo ou anômalo detectado
- Incidente de segurança em investigação
- Manutenção emergencial que requer parada total dos agentes
- Credenciais de agente comprometidas (enquanto a revogação é processada)
- Qualquer situação em que a incerteza sobre o estado do sistema justifica parar tudo

**Regra geral:** em caso de dúvida, ative o kill switch primeiro e investigue depois.
O custo de uma parada falsa é muito menor que o custo de uma ação destrutiva não contida.

---

## Ativação

### Método 1 — Linha de comando (mais rápido)

```bash
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) | [motivo do incidente]" > .kill_switch
```

### Método 2 — Python

```python
from governance.approval.gate import ApprovalGate
gate = ApprovalGate()  # use o caminho configurado da sua instalação
gate.activate_kill_switch("P0: incidente de segurança — [descrever]")
```

### Verificação

```bash
# O arquivo deve existir e conter o motivo
cat .kill_switch

# Teste rápido via Python
python3 -c "
from governance.approval.gate import ApprovalGate
gate = ApprovalGate()
print('Kill switch ativo:', gate.is_kill_switch_active())
"
```

---

## Efeito imediato

Após a ativação, toda tentativa de execução de ferramenta por qualquer agente
resulta em:

```
GovernanceError: Kill switch ativo — todas as ações bloqueadas.
Motivo: 2025-06-01T10:30:00Z | P0: incidente de segurança
```

O evento é registrado na trilha de auditoria como `kill_switch_triggered`.

---

## Desativação

**Só desative após confirmar que:**
1. O agente problemático foi identificado
2. As credenciais foram revogadas (se necessário)
3. A política foi atualizada para prevenir recorrência
4. Um humano responsável autorizou a retomada

### Método 1 — Linha de comando

```bash
rm .kill_switch
```

### Método 2 — Python

```python
gate.deactivate_kill_switch()
```

---

## Diagnóstico pós-ativação

```bash
# Ver os últimos eventos de kill switch no log
python3 -c "
import json
with open('audit_logs/producao/audit.jsonl') as f:
    for line in f:
        event = json.loads(line)
        if 'kill_switch' in event['event_type']:
            print(event['timestamp'], event['event_type'], event.get('agent_id'))
"
```

---

## Considerações de deploy

Em produção, o arquivo `.kill_switch` deve estar no mesmo diretório configurado
na variável `GOVERNANCE_KILL_SWITCH_FILE` do `.env`. O diretório deve ter
permissões que permitam criação de arquivo por operadores autorizados mas não
por processos de agente.
