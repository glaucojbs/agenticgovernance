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
