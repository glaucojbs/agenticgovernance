"""
Pacote principal de governança agêntica.

Importações de conveniência para os subsistemas principais.
"""

from governance.approval.gate import ApprovalGate
from governance.audit.logger import AuditLogger
from governance.budget.guard import BudgetGuard
from governance.identity.models import AgentIdentity, AgentScope, DelegationChain
from governance.policy.engine import PolicyDecision, PolicyEngine, PolicyResult
from governance.registry.catalog import AgentRegistry, ToolRegistry
from governance.runtime.governed import GovernedAgentRuntime

__all__ = [
    "AgentIdentity",
    "DelegationChain",
    "AgentScope",
    "PolicyEngine",
    "PolicyDecision",
    "PolicyResult",
    "AuditLogger",
    "BudgetGuard",
    "ApprovalGate",
    "AgentRegistry",
    "ToolRegistry",
    "GovernedAgentRuntime",
]
