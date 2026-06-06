"""Testes do PolicyDryRun (simulação de mudança de política)."""

import shutil
from pathlib import Path

from governance.identity.models import AgentEnvironment, AgentScope
from governance.policy.dryrun import PolicyDryRun
from governance.policy.engine import ActionRequest, RiskLevel

POLICIES_DIR = Path(__file__).parent.parent / "policies"


def _requests(envs=("dev", "prod")):
    return [
        ActionRequest(
            agent_id="t",
            agent_name="Test",
            tool_name=tool,
            parameters={},
            environment=AgentEnvironment(env),
            scopes=[AgentScope.READ_FILES, AgentScope.READ_DATABASE],
            risk_level=RiskLevel.LOW,
        )
        for tool in ["read_files", "query_database"]
        for env in envs
    ]


def _proposed_dir(tmp_path, extra_yaml):
    proposed = tmp_path / "proposed"
    proposed.mkdir()
    for f in POLICIES_DIR.glob("*.yaml"):
        shutil.copy(f, proposed / f.name)
    # Prefixo "00-" garante avaliação antes das regras ALLOW existentes
    # (o engine retorna na primeira regra que casa, em ordem alfabética de arquivo).
    (proposed / "00-extra.yaml").write_text(extra_yaml)
    return proposed


class TestPolicyDryRun:
    def test_no_change_when_identical(self, tmp_path):
        proposed = _proposed_dir(tmp_path, "rules: []\n")
        dry = PolicyDryRun.from_dirs(POLICIES_DIR, proposed)
        report = dry.compare(_requests())
        assert report.total == len(_requests())
        assert not report.restrictions

    def test_restriction_detected(self, tmp_path):
        proposed = _proposed_dir(
            tmp_path,
            """rules:
  - name: deny-read-files-all
    decision: DENY
    tools: [read_files]
    reason: "nova restrição"
""",
        )
        dry = PolicyDryRun.from_dirs(POLICIES_DIR, proposed)
        report = dry.compare(_requests())
        assert report.restrictions
        comp = report.restrictions[0]
        assert comp.is_restriction
        assert comp.changed
        assert "read_files" in comp.summary()

    def test_render_runs(self, tmp_path):
        proposed = _proposed_dir(tmp_path, "rules: []\n")
        report = PolicyDryRun.from_dirs(POLICIES_DIR, proposed).compare(_requests())
        assert "POLICY DRY-RUN REPORT" in report.render()
