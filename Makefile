.PHONY: setup test demo eval lint clean help

PYTHON := python3
VENV   := .venv
PIP    := $(VENV)/bin/pip
PY     := $(VENV)/bin/python

## help: mostra esta mensagem de ajuda
help:
	@grep -E '^## ' Makefile | sed 's/## //'

## setup: cria o virtualenv e instala as dependências
setup:
	$(PYTHON) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	@echo "✓ Ambiente configurado. Ative com: source $(VENV)/bin/activate"

## lint: executa ruff (format check + lint)
lint:
	$(VENV)/bin/ruff check src/ tests/ examples/ evals/
	$(VENV)/bin/ruff format --check src/ tests/ examples/ evals/

## format: corrige formatação automaticamente
format:
	$(VENV)/bin/ruff check --fix src/ tests/ examples/ evals/
	$(VENV)/bin/ruff format src/ tests/ examples/ evals/

## test: roda os testes unitários com cobertura
test:
	$(VENV)/bin/pytest tests/ --cov=src/governance --cov-report=term-missing

## stack: sobe a stack Docker (Jaeger + Prometheus + Grafana + OPA)
stack:
	docker compose up -d
	@echo "✓ Stack iniciada:"
	@echo "  Jaeger  : http://localhost:16686"
	@echo "  Grafana : http://localhost:3000  (admin/admin)"
	@echo "  OPA     : http://localhost:8181"
	@echo "  Prometheus: http://localhost:9090"

## stack-down: derruba a stack Docker
stack-down:
	docker compose down

## demo-observability: roda exemplos com OTEL apontando para Jaeger local
demo-observability:
	OTEL_EXPORTER=otlp OTEL_ENDPOINT=http://localhost:4318 $(PY) -m examples.02_governed_agent
	OTEL_EXPORTER=otlp OTEL_ENDPOINT=http://localhost:4318 $(PY) -m examples.05_production_stack

## demo: roda todos os exemplos em sequência
demo:
	@echo "============================================================"
	@echo " EXEMPLO 01 — Agente sem governança (anti-exemplo)"
	@echo "============================================================"
	$(PY) -m examples.01_ungoverned_agent
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 02 — Agente com governança completa"
	@echo "============================================================"
	$(PY) -m examples.02_governed_agent
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 03 — Delegação multi-agente"
	@echo "============================================================"
	$(PY) -m examples.03_multi_agent_delegation
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 04 — Ação de alto risco com aprovação humana"
	@echo "============================================================"
	$(PY) -m examples.04_high_risk_approval
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 05 — Stack de produção (OTEL + Ed25519 + Anomaly + OPA)"
	@echo "============================================================"
	$(PY) -m examples.05_production_stack
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 06 — Análise Forense de Incidente"
	@echo "============================================================"
	$(PY) -m examples.06_forensics
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 07 — Plataforma Multi-Tenant"
	@echo "============================================================"
	$(PY) -m examples.07_multi_tenant
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 08 — Compliance, PII Masking e Dry-run"
	@echo "============================================================"
	$(PY) -m examples.08_compliance_report
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 09 — Guardrails de conteúdo (prompt injection / DLP)"
	@echo "============================================================"
	$(PY) -m examples.09_guardrails
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 10 — Integridade de ferramentas e MCP (supply chain)"
	@echo "============================================================"
	$(PY) -m examples.10_tool_integrity
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 11 — Memória governada + comunicação A2A assinada"
	@echo "============================================================"
	$(PY) -m examples.11_memory_a2a
	@echo ""
	@echo "============================================================"
	@echo " EXEMPLO 12 — Padrões 2025/2026 (OTel GenAI + OWASP Agentic + GPAI)"
	@echo "============================================================"
	$(PY) -m examples.12_standards_report

## eval: roda o eval gate (falha se qualquer barreira não segurar)
eval:
	@echo "Rodando eval gate..."
	PYTHONPATH=$(PWD) $(PY) evals/run_evals.py

## clean: remove artefatos gerados
clean:
	rm -rf $(VENV) __pycache__ .pytest_cache .coverage htmlcov .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf audit_logs/ .kill_switch
