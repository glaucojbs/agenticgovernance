# AGENTS.md

## Projeto

Repositório de referência para governança de agentes de IA autônomos.

## Contrato de neutralidade

- Não introduza dependência obrigatória de um provedor, modelo ou ferramenta de agente.
- Mantenha runtime, policy, identity, audit, approval, registry, guardrails e supply chain independentes de SDKs específicos.
- Integrações com OpenAI, Anthropic, Azure, Ollama, modelos locais ou outras LLMs devem entrar por adapters ou pontos de extensão explícitos.
- Configurações locais de ferramentas como Claude Code, Codex, Cursor ou Windsurf não fazem parte do contrato arquitetural do repositório.
- Toda ação sensível deve passar pelo `GovernedAgentRuntime`.
- Preserve default-deny, privilégio mínimo, auditabilidade, eval gates e testes adversariais.

## Comandos

- Setup: `make setup`
- Testes: `make test`
- Lint: `.venv/bin/ruff check .`
- Evals: `make eval`
- Demo: `make demo`
- Stack de observabilidade: `make stack`

## Diretrizes de implementação

- Prefira interfaces, protocolos e adapters a imports diretos de SDKs de provedores no domínio.
- Registre provider/model/runtime como metadados observáveis, não como fonte de decisão de autorização.
- Políticas devem autorizar capacidades, ferramentas e escopos, não marcas de modelo.
- Mudanças em controles de governança devem vir acompanhadas de testes ou evals proporcionais ao risco.
- Mudanças arquiteturais relevantes devem ser registradas em ADR.

## Antes de finalizar

- Rode os testes relevantes.
- Rode `make eval` se alterar policy, runtime, guardrails, registry, supply chain, memória ou A2A.
- Atualize documentação quando mudar comportamento, contratos públicos ou decisões arquiteturais.
