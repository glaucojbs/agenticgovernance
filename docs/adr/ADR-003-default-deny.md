# ADR-003 — Princípio de Default-Deny

**Status:** Aceito  
**Data:** 2025-06-01  
**Autores:** Time de Plataforma de IA

---

## Contexto

Ao projetar o motor de política, a questão fundamental era:

> **O que acontece quando nenhuma regra cobre a ação solicitada?**

Duas filosofias possíveis:

- **Default-allow**: sem regra explícita → permitido
- **Default-deny**: sem regra explícita → negado

## Decisão

Adotamos **default-deny** como comportamento padrão do motor de política.

## Motivação

### Por que default-allow é perigoso para agentes de IA

Agentes de IA podem ser instruídos (via prompt injection ou comportamento
emergente) a tentar executar ações não antecipadas pelos desenvolvedores.
Com default-allow, qualquer nova ferramenta adicionada ao catálogo é
automaticamente acessível a todos os agentes até que uma regra de negação
seja criada — **a janela de exposição é o intervalo entre o deploy e a criação
da regra**.

### Falha segura vs. falha aberta

| Situação | Default-allow | Default-deny (escolhido) |
|----------|--------------|-------------------------|
| Nova ferramenta adicionada sem política | ✓ Acessível a todos | ✗ Negada até política criada |
| Política incorreta / esquecida | ✓ Agente opera | ✗ Agente bloqueado |
| Ataque de enumeração de ferramentas | Atacante descobre o que funciona | Silenciosamente negado |
| Erro de configuração | Exposição silenciosa | Falha barulhenta e auditada |

Em sistemas de segurança, **falha barulhenta é preferível a falha silenciosa**.
Um agente bloqueado cria um alerta visível; um agente com acesso indevido pode
operar indefinidamente sem ser detectado.

### Custo operacional

O custo de default-deny é a necessidade de criar políticas ALLOW explícitas para
cada ferramenta que cada agente precisa usar. Este custo é deliberado:

> **Cada política ALLOW é uma decisão documentada, revisada e auditada.**

Não ter a política escrita não significa que a permissão não deveria existir —
significa que ninguém tomou explicitamente a decisão de concedê-la.

## Consequências

**Positivas:**
- Superfície de ataque mínima por padrão
- Qualquer nova ferramenta começa bloqueada até análise explícita
- Falhas de configuração se manifestam como negações (detectáveis), não como
  exposições (silenciosas)

**Negativas / Limitações:**
- Requer criação proativa de políticas ALLOW para ferramentas legítimas
- Pode causar fricção em fases iniciais de desenvolvimento (muitas negações)
- Depende de cultura de equipe que encare a criação de políticas como investimento,
  não como burocracia

## Implementação

```python
# PolicyEngine.evaluate() — trecho relevante
if approval_result:
    return approval_result

# Default-deny: nenhuma regra ALLOW bateu
return PolicyResult(
    decision=PolicyDecision.DENY,
    reason=(
        f"Nenhuma política permite a ação '{request.tool_name}' "
        f"para o agente '{request.agent_name}' (default-deny)"
    ),
)
```

O arquivo `policies/default-deny.yaml` existe como documentação explícita deste
princípio — ele não contém regras, mas sua presença sinaliza que a ausência de
regras é intencional.
