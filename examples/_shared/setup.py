"""
Helpers compartilhados entre os exemplos.

Monta um GovernedAgentRuntime com ferramentas simuladas e políticas reais.
Cada exemplo pode chamar build_runtime() e personalizar conforme necessário.
"""

from __future__ import annotations

from pathlib import Path

from governance.approval.gate import ApprovalGate
from governance.audit.logger import AuditLogger
from governance.budget.guard import BudgetConfig, BudgetGuard
from governance.identity.models import AgentEnvironment, AgentIdentity, AgentScope
from governance.policy.engine import PolicyEngine, RiskLevel
from governance.registry.catalog import (
    AgentRegistry,
    ToolDefinition,
    ToolRegistry,
)
from governance.runtime.governed import GovernedAgentRuntime

POLICIES_DIR = Path(__file__).parent.parent.parent / "policies"
AUDIT_DIR = Path("audit_logs")


# ── Ferramentas simuladas ──────────────────────────────────────────────────────

def _tool_read_files(path: str = "/data") -> str:
    return f"[SIMULADO] Conteúdo do arquivo: {path!r} → {{dados: [1, 2, 3], versao: '1.0'}}"


def _tool_list_files(directory: str = "/data") -> str:
    return f"[SIMULADO] Arquivos em {directory!r}: ['report.csv', 'config.json', 'README.md']"


def _tool_query_database(query: str = "SELECT 1") -> str:
    return f"[SIMULADO] Resultado de '{query}': 42 linhas retornadas"


def _tool_delete_files(path: str = "/data") -> str:
    # Esta implementação nunca deveria ser chamada — a política nega antes
    return f"[SIMULADO] ARQUIVOS APAGADOS: {path}"


def _tool_send_email(to: str = "", subject: str = "", body: str = "") -> str:
    return f"[SIMULADO] E-mail enviado para {to!r}: {subject!r}"


def _tool_call_internal_api(endpoint: str = "/api/v1/data", method: str = "GET") -> str:
    return f"[SIMULADO] {method} {endpoint} → 200 OK {{status: 'success'}}"


def _tool_wipe_database(confirm: str = "") -> str:
    # Esta implementação nunca deveria ser chamada
    return "[SIMULADO] BANCO APAGADO COMPLETAMENTE"


def make_mock_llm(scripted: list[str] | None = None):
    """Cria um MockLlmProvider offline para os exemplos da camada LLM."""
    from governance.llm.mock import MockLlmProvider

    return MockLlmProvider(scripted=scripted)


def build_runtime(
    audit_subdir: str = "default",
    auto_approve: bool = False,
    auto_deny: bool = False,
    kill_switch_path: Path | None = None,
    budget_config: BudgetConfig | None = None,
    approver_callback=None,
    interactive: bool = False,
) -> tuple[GovernedAgentRuntime, AuditLogger, ApprovalGate, ToolRegistry, AgentRegistry]:
    """
    Constrói um runtime governado completo com ferramentas simuladas.

    Retorna (runtime, audit_logger, approval_gate, tool_registry, agent_registry)
    para que os exemplos possam interagir com os subsistemas diretamente.
    """
    # Diretório de auditoria específico por exemplo
    log_dir = AUDIT_DIR / audit_subdir
    log_dir.mkdir(parents=True, exist_ok=True)
    audit = AuditLogger(log_dir / "audit.jsonl")

    budget = BudgetGuard(budget_config or BudgetConfig(
        max_cost_usd=1.0,
        max_tokens=50_000,
        max_calls=100,
        max_calls_per_minute=60,
    ))

    ks_path = kill_switch_path or Path(f".kill_switch_{audit_subdir}")
    # Garante que o kill switch começa desativado
    if ks_path.exists():
        ks_path.unlink()

    approval = ApprovalGate(
        kill_switch_path=ks_path,
        auto_approve=auto_approve,
        auto_deny=auto_deny,
        approver_callback=approver_callback,
        interactive=interactive,
    )

    # ── Registro de ferramentas ──────────────────────────────────────────────
    tools = ToolRegistry()
    tools.register(
        ToolDefinition(
            name="read_files",
            description="Lê o conteúdo de arquivos",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.READ_FILES,
        ),
        implementation=_tool_read_files,
    )
    tools.register(
        ToolDefinition(
            name="list_files",
            description="Lista arquivos em um diretório",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.READ_FILES,
        ),
        implementation=_tool_list_files,
    )
    tools.register(
        ToolDefinition(
            name="query_database",
            description="Executa query de leitura no banco",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.READ_DATABASE,
        ),
        implementation=_tool_query_database,
    )
    tools.register(
        ToolDefinition(
            name="delete_files",
            description="Apaga arquivos permanentemente",
            risk_level=RiskLevel.HIGH,
            required_scope=AgentScope.DELETE_FILES,
            is_destructive=True,
            is_reversible=False,
        ),
        implementation=_tool_delete_files,
    )
    tools.register(
        ToolDefinition(
            name="send_email",
            description="Envia e-mail para destinatários",
            risk_level=RiskLevel.MEDIUM,
            required_scope=AgentScope.SEND_EMAIL,
        ),
        implementation=_tool_send_email,
    )
    tools.register(
        ToolDefinition(
            name="call_internal_api",
            description="Chama APIs internas da organização",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.CALL_INTERNAL_API,
        ),
        implementation=_tool_call_internal_api,
    )
    tools.register(
        ToolDefinition(
            name="wipe_database",
            description="Apaga completamente o banco de dados",
            risk_level=RiskLevel.CRITICAL,
            required_scope=AgentScope.DELETE_FILES,
            is_destructive=True,
            is_reversible=False,
        ),
        implementation=_tool_wipe_database,
    )

    # ── Registry de agentes ──────────────────────────────────────────────────
    agents = AgentRegistry()

    runtime = GovernedAgentRuntime(
        policy_engine=PolicyEngine(POLICIES_DIR),
        audit_logger=audit,
        budget_guard=budget,
        approval_gate=approval,
        tool_registry=tools,
        agent_registry=agents,
    )

    return runtime, audit, approval, tools, agents


def make_identity(
    agent_id: str,
    name: str,
    owner: str,
    scopes: list[AgentScope],
    environment: AgentEnvironment = AgentEnvironment.DEV,
    parent_id: str | None = None,
    version: str = "1.0.0",
) -> AgentIdentity:
    """Cria e autentica uma identidade de agente."""
    identity = AgentIdentity(
        id=agent_id,
        name=name,
        owner=owner,
        environment=environment,
        scopes=scopes,
        parent_id=parent_id,
        version=version,
    )
    identity.issue_credential(ttl_seconds=3600)
    return identity


def print_header(title: str) -> None:
    width = 60
    print("\n" + "═" * width)
    print(f"  {title}")
    print("═" * width)


def print_result(action: str, result) -> None:
    status = "✓ PERMITIDO" if result.success else "✗ BLOQUEADO"
    print(f"\n  {status}  │  {action}")
    if result.success:
        print(f"           │  Política  : {result.policy_decision}")
        print(f"           │  Saída     : {result.output}")
    else:
        print(f"           │  Motivo    : {result.error}")
    if result.audit_sequence:
        print(f"           │  Audit seq : #{result.audit_sequence}")


def print_audit_trail(audit: AuditLogger) -> None:
    print_header("TRILHA DE AUDITORIA")
    events = audit.replay()
    for event in events:
        ts = event.timestamp[11:19]  # HH:MM:SS
        agent = event.agent_name or "-"
        tool = event.tool_name or "-"
        decision = event.details.get("decision", "")
        reason_short = event.details.get("reason", "")[:50]
        print(
            f"  #{event.sequence:02d} [{ts}] {event.event_type.value:<22}"
            f" | agente={agent} ferramenta={tool}"
        )
        if decision:
            print(f"       decisão={decision}  motivo={reason_short}")
    print()


def print_chain_verification(audit: AuditLogger) -> None:
    result = audit.verify_chain()
    if result.valid:
        print(f"\n  ✓ Hash chain VÁLIDA ({result.total_entries} entradas verificadas)")
    else:
        print(f"\n  ✗ Hash chain INVÁLIDA: {result.error}")
