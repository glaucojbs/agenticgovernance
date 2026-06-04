# agent_policy.rego — Política de governança carregada no servidor OPA.
#
# Este arquivo é a versão executável das regras em policies/example-readonly-agent.yaml.
# O runtime chama: POST /v1/data/governance/decision
#
# Input esperado:
#   {"input": {"tool_name": "...", "scopes": [...], "environment": "...",
#               "risk_level": "...", "agent_id": "...", "parameters": {}}}

package governance

import future.keywords.if
import future.keywords.in

# ── Ferramentas sempre negadas ────────────────────────────────────────────────

destructive_tools := {"delete_files", "drop_table", "wipe_database"}

deny_reasons[reason] if {
    input.tool_name in destructive_tools
    reason := sprintf("ferramenta '%v' é destrutiva — negada por política", [input.tool_name])
}

deny_reasons[reason] if {
    input.tool_name == "read_secrets"
    not "read:secrets" in input.scopes
    reason := "acesso a segredos requer escopo 'read:secrets' explícito"
}

# ── Aprovação humana ──────────────────────────────────────────────────────────

high_risk_levels := {"high", "critical"}
non_dev_envs := {"staging", "prod"}

approval_reasons[reason] if {
    input.risk_level in high_risk_levels
    count(deny_reasons) == 0
    reason := sprintf("risco '%v' requer aprovação humana", [input.risk_level])
}

approval_reasons[reason] if {
    input.tool_name == "send_email"
    input.environment in non_dev_envs
    "send:email" in input.scopes
    count(deny_reasons) == 0
    reason := "envio de e-mail em produção requer aprovação"
}

# ── Allow ─────────────────────────────────────────────────────────────────────

allow if {
    input.tool_name in {"read_files", "list_files"}
    "read:files" in input.scopes
    not input.risk_level in high_risk_levels
    count(deny_reasons) == 0
    count(approval_reasons) == 0
}

allow if {
    input.tool_name in {"query_database", "read_database"}
    "read:database" in input.scopes
    not input.risk_level in high_risk_levels
    count(deny_reasons) == 0
    count(approval_reasons) == 0
}

allow if {
    input.tool_name == "send_email"
    "send:email" in input.scopes
    input.environment == "dev"
    not input.risk_level in high_risk_levels
    count(deny_reasons) == 0
    count(approval_reasons) == 0
}

allow if {
    input.tool_name == "call_internal_api"
    "call:internal_api" in input.scopes
    not input.risk_level in high_risk_levels
    count(deny_reasons) == 0
    count(approval_reasons) == 0
}

# ── Decisão final (exposta via /v1/data/governance/decision) ─────────────────

default decision := "DENY"

decision := "DENY" if count(deny_reasons) > 0
decision := "REQUIRE_APPROVAL" if {
    count(deny_reasons) == 0
    count(approval_reasons) > 0
}
decision := "ALLOW" if allow
