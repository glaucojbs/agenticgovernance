# agent_policy.rego
#
# Equivalente Rego das regras em example-readonly-agent.yaml.
# Ilustrativo — não é executado pelo runtime deste repositório.
#
# Para testar: opa eval -d agent_policy.rego -I 'data.governance.allow'

package governance

import future.keywords.if
import future.keywords.in

# ── Ferramentas destrutivas — negadas sempre ─────────────────────────────────

destructive_tools := {"delete_files", "drop_table", "wipe_database"}

deny[reason] if {
    input.tool_name in destructive_tools
    reason := sprintf(
        "ferramenta '%v' é destrutiva e explicitamente negada pela política",
        [input.tool_name]
    )
}

# ── Segredos exigem escopo explícito ─────────────────────────────────────────

deny[reason] if {
    input.tool_name == "read_secrets"
    not "read:secrets" in input.scopes
    reason := "acesso a segredos requer escopo 'read:secrets'"
}

# ── Risco alto → aprovação humana ────────────────────────────────────────────

high_risk_levels := {"high", "critical"}

require_approval[reason] if {
    input.risk_level in high_risk_levels
    not deny[_]   # só avalia se não há DENY
    reason := sprintf(
        "ação de risco '%v' requer aprovação humana",
        [input.risk_level]
    )
}

# ── E-mail em staging/prod → aprovação ───────────────────────────────────────

non_dev_envs := {"staging", "prod"}

require_approval[reason] if {
    input.tool_name == "send_email"
    input.environment in non_dev_envs
    "send:email" in input.scopes
    not deny[_]
    reason := "envio de e-mail em produção requer aprovação"
}

# ── Leitura de arquivos — permitida ──────────────────────────────────────────

allow if {
    input.tool_name in {"read_files", "list_files"}
    "read:files" in input.scopes
    not input.risk_level in high_risk_levels
    not deny[_]
    not require_approval[_]
}

# ── Leitura de banco — permitida ─────────────────────────────────────────────

allow if {
    input.tool_name in {"query_database", "read_database"}
    "read:database" in input.scopes
    not input.risk_level in high_risk_levels
    not deny[_]
    not require_approval[_]
}

# ── Decisão final ─────────────────────────────────────────────────────────────

decision := "DENY"         if count(deny) > 0
decision := "REQUIRE_APPROVAL" if count(deny) == 0; count(require_approval) > 0
decision := "ALLOW"        if allow
decision := "DENY"         if not allow; count(deny) == 0; count(require_approval) == 0
