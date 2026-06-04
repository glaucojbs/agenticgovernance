"""
Pacote principal de governança agêntica.

Importações de conveniência para os subsistemas principais.
"""

from governance.identity.models import AgentIdentity, DelegationChain, AgentScope
from governance.policy.engine import PolicyEngine, PolicyDecision, PolicyResult
from governance.audit.logger import AuditLogger
from governance.budget.guard import BudgetGuard
from governance.approval.gate import ApprovalGate
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
