"""Testes para os catálogos de ferramentas e agentes."""

import pytest

from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.engine import RiskLevel
from governance.registry.catalog import (
    AgentRecord,
    AgentRegistry,
    ToolDefinition,
    ToolRegistry,
)


class TestToolRegistry:
    def make_tool(self, name: str = "read_files") -> ToolDefinition:
        return ToolDefinition(
            name=name,
            description="Reads files from the filesystem",
            risk_level=RiskLevel.LOW,
            required_scope=AgentScope.READ_FILES,
        )

    def test_register_and_get(self) -> None:
        registry = ToolRegistry()
        tool = self.make_tool()
        registry.register(tool)
        assert registry.get("read_files") is not None

    def test_get_unknown_returns_none(self) -> None:
        registry = ToolRegistry()
        assert registry.get("nonexistent") is None

    def test_register_with_implementation(self) -> None:
        registry = ToolRegistry()
        tool = self.make_tool()
        impl = lambda: "result"  # noqa: E731
        registry.register(tool, implementation=impl)
        assert registry.get_implementation("read_files") is impl

    def test_is_allowed_in_environment(self) -> None:
        registry = ToolRegistry()
        tool = ToolDefinition(
            name="prod_only_tool",
            description="Only for prod",
            risk_level=RiskLevel.HIGH,
            required_scope=AgentScope.WRITE_DATABASE,
            allowed_environments=[AgentEnvironment.PROD],
        )
        registry.register(tool)
        assert registry.is_allowed_in_environment("prod_only_tool", AgentEnvironment.PROD)
        assert not registry.is_allowed_in_environment("prod_only_tool", AgentEnvironment.DEV)

    def test_list_tools(self) -> None:
        registry = ToolRegistry()
        registry.register(self.make_tool("tool1"))
        registry.register(self.make_tool("tool2"))
        assert len(registry.list_tools()) == 2


class TestAgentRegistry:
    def make_record(self, agent_id: str = "agent-001") -> AgentRecord:
        return AgentRecord(
            agent_id=agent_id,
            name="Test Agent",
            version="1.0.0",
            owner="owner@example.com",
        )

    def test_register_agent(self) -> None:
        registry = AgentRegistry()
        record = self.make_record()
        registry.register(record)
        assert registry.get("agent-001") is not None

    def test_duplicate_registration_raises(self) -> None:
        registry = AgentRegistry()
        registry.register(self.make_record())
        with pytest.raises(ValueError, match="já cadastrado"):
            registry.register(self.make_record())

    def test_registered_agent_cannot_run_in_prod(self) -> None:
        registry = AgentRegistry()
        registry.register(self.make_record())
        assert not registry.can_run_in_prod("agent-001")

    def test_approved_agent_can_run_in_prod(self) -> None:
        registry = AgentRegistry()
        registry.register(self.make_record())
        registry.approve("agent-001", eval_report="eval-2025-v1")
        assert registry.can_run_in_prod("agent-001")

    def test_deprecated_agent_cannot_run_in_prod(self) -> None:
        registry = AgentRegistry()
        registry.register(self.make_record())
        registry.approve("agent-001")
        registry.deprecate("agent-001")
        assert not registry.can_run_in_prod("agent-001")

    def test_approve_unknown_raises(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(ValueError, match="não encontrado"):
            registry.approve("nonexistent")
