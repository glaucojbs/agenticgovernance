# 09 — Mapeamento de Compliance

> **Aviso importante:** Este mapeamento é **ilustrativo e educacional**.
> Não constitui aconselhamento jurídico, de conformidade regulatória ou de certificação.
> Consulte especialistas em compliance antes de usar este repositório como base
> para declarações regulatórias.

---

## NIST AI Risk Management Framework (AI RMF 1.0)

| Função | Sub-função | Controle neste repositório |
|--------|-----------|---------------------------|
| **GOVERN** | Políticas organizacionais | `policies/*.yaml` — regras declarativas versionadas |
| **GOVERN** | Papéis e responsabilidades | `docs/02-modelo-de-governanca.md` — RACI |
| **GOVERN** | Ciclo de vida de IA | `src/governance/registry/` — registered/approved/deprecated |
| **MAP** | Classificação de risco | `src/governance/policy/engine.py` — `RiskLevel` enum |
| **MAP** | Identificação de partes interessadas | `AgentIdentity.owner` — humano responsável rastreável |
| **MEASURE** | Avaliação contínua | `evals/run_evals.py` — eval gate automatizado |
| **MEASURE** | Monitoramento de comportamento | `src/governance/audit/` — every action logged |
| **MANAGE** | Respostas a incidentes | `runbooks/incident-response.md` |
| **MANAGE** | Contenção de impacto | `src/governance/budget/` + kill switch |
| **MANAGE** | Revogação de acesso | `IdentityManager.revoke()` + `revoke_scope()` |

---

## ISO/IEC 42001:2023 — AI Management System

| Cláusula | Requisito | Controle neste repositório |
|----------|-----------|---------------------------|
| 6.1 | Avaliação de riscos de IA | `docs/07-classificacao-de-risco.md` + threat model |
| 6.2 | Objetivos e planejamento | `docs/02-modelo-de-governanca.md` |
| 8.2 | Ciclo de vida do sistema de IA | `docs/08-ciclo-de-vida.md` |
| 8.3 | Dados para sistemas de IA | Auditoria de todas as ações sobre dados |
| 8.4 | Registro e documentação | `src/governance/audit/` — audit trail completo |
| 9.1 | Monitoramento e avaliação | `evals/` + `audit/logger.py` |
| 10.1 | Melhoria contínua | Eval gate como portão de regressão |

---

## EU AI Act (Regulamento UE 2024/1689)

| Artigo / Requisito | Categoria | Controle neste repositório |
|-------------------|-----------|---------------------------|
| Art. 9 — Risk Management System | Alto risco | `RiskLevel` + `ApprovalGate` + kill switch |
| Art. 10 — Data Governance | Alto risco | Auditoria de acesso a dados |
| Art. 12 — Record-keeping | Alto risco | Audit log JSONL com hash chain |
| Art. 13 — Transparency | Alto risco | `AgentIdentity.owner` + delegation chain |
| Art. 14 — Human Oversight | Alto risco | `ApprovalGate` HITL + kill switch |
| Art. 15 — Accuracy & Robustness | Alto risco | Budget guard + timeout + eval gate |
| Art. 26 — Obligations for deployers | Qualquer risco | Registry + lifecycle management |
| Art. 71 — General purpose AI (GPAI) | GPAI | Escopos explícitos + default-deny |

---

## OWASP Top 10 for LLM Applications (2025)

| # | Vulnerabilidade | Mitigação neste repositório |
|---|----------------|----------------------------|
| LLM01 | **Prompt Injection** | Policy engine valida ação final, não o prompt; escopos limitam o que pode ser executado |
| LLM02 | **Insecure Output Handling** | Ferramentas são declaradas com tipos; runtime não interpreta saída como código |
| LLM03 | **Training Data Poisoning** | Fora do escopo (runtime de inferência, não treino) |
| LLM04 | **Model Denial of Service** | BudgetGuard com limite de tokens, chamadas e rate limit |
| LLM05 | **Supply Chain Vulnerabilities** | Ferramentas registradas explicitamente; nenhuma execução dinâmica |
| LLM06 | **Sensitive Information Disclosure** | `read:secrets` é escopo separado e requer política explícita |
| LLM07 | **Insecure Plugin Design** | ToolRegistry com metadados de segurança por ferramenta |
| LLM08 | **Excessive Agency** | Default-deny + escopos mínimos + BudgetGuard |
| LLM09 | **Overreliance** | Approval gate para ações de alto risco |
| LLM10 | **Model Theft** | Fora do escopo; credenciais de curta duração reduzem exposição |

---

## OWASP Top 10 for Agentic AI (2025 — draft)

| # | Vulnerabilidade | Mitigação neste repositório |
|---|----------------|----------------------------|
| Agentic01 | **Unbounded Agent Actions** | Default-deny + escopos explícitos + BudgetGuard |
| Agentic02 | **Insufficient Human Oversight** | ApprovalGate HITL + kill switch global |
| Agentic03 | **Insecure Agent Communication** | DelegationChain rastreável; sub-agentes não herdam escopos |
| Agentic04 | **Resource Exhaustion** | BudgetGuard (custo, tokens, chamadas, rate) |
| Agentic05 | **Lack of Auditability** | Audit log com hash chain + verify_chain() |
| Agentic06 | **Privilege Escalation** | DelegationChain.add_link() previne escalada |
| Agentic07 | **Unsafe Tool Invocation** | ToolRegistry + policy engine antes de qualquer execução |
| Agentic08 | **Identity Spoofing** | AgentIdentity com credenciais de curta duração |
| Agentic09 | **Uncontrolled Subagent Spawning** | `spawn:subagent` como escopo explícito |
| Agentic10 | **Inadequate Incident Response** | Kill switch + runbooks operacionais |

---

## OWASP Top 10 for Agentic Applications (dez/2025)

O benchmark de referência para segurança de aplicações agênticas. O `ComplianceReporter`
mapeia eventos do audit log para estes controles (framework `OWASP Agentic`):

| ID | Ameaça | Defesa neste repositório |
|----|--------|--------------------------|
| ASI01 | **Agent Goal Hijacking** | Guardrails de conteúdo (prompt injection in/out) — `guardrails/` |
| ASI02 | **Identity & Privilege Abuse** | Escopos explícitos + cadeia de delegação + `ACTION_DENIED` |
| ASI04 | **Insecure Inter-Agent Communication** | Canal A2A assinado + nonce — `a2a/` |
| ASI06 | **Tool Misuse & Exploitation** | Integridade de ferramentas + guardrails — `supply_chain/` |
| ASI07 | **Agentic Supply Chain** | Fingerprint assinada + allowlist MCP + AI-BOM — `supply_chain/` |
| ASI09 | **Memory & Context Poisoning** | Memória governada + quarentena — `memory/` |

## EU AI Act — obrigações GPAI (em vigor desde ago/2025)

| Obrigação (Art.53/55) | Evidência |
|-----------------------|-----------|
| Documentação técnica / model card | `generate_model_card()` — `compliance/model_card.py` |
| Inventário de componentes | AI-BOM — `supply_chain/aibom.py` |
| Post-market monitoring | Audit log + telemetria + anomaly detector |
| Reporte de incidentes / mitigação de risco sistêmico | `GUARDRAIL_BLOCKED`, kill switch, runbooks |

## NIST GenAI Profile (AI 600-1)

As 12 categorias de risco do NIST GenAI estão disponíveis em
`NIST_GENAI_RISK_CATEGORIES` e são referenciadas no model card. Os guardrails endereçam
diretamente **Information Integrity**, **Data Privacy** e **Information Security**.

> Nota: nenhum dos frameworks "clássicos" (EU AI Act, NIST RMF, ISO 42001) foi desenhado
> para agentes autônomos; este repositório os **estende** com os controles agênticos acima.

---

*Última atualização: 2026. Os frameworks referenciados estão sujeitos a revisão.*
*Verifique sempre as versões mais recentes nos sites oficiais dos publicadores.*
