# ADR-009: Neutralidade de Provedor e Ferramenta de Agente

## Status

Aceito.

## Contexto

O repositório existe para demonstrar governança de agentes de IA, não para promover ou
depender de uma LLM, provedor ou ferramenta de desenvolvimento específica.

Ferramentas como Claude Code, Codex, Cursor, Windsurf ou pipelines de CI podem operar o
mesmo código-fonte. Provedores como OpenAI, Anthropic, Azure, Ollama ou modelos locais
podem ser usados por agentes em produção. Se essas escolhas vazarem para o domínio de
governança, o sistema fica mais acoplado, menos portável e mais caro de manter.

## Decisão

O domínio de governança deve permanecer provider-agnostic e tool-agnostic.

- `AGENTS.md` é a fonte canônica de instruções para agentes que operam o repositório.
- Arquivos específicos de ferramenta, quando existirem, devem ser pontes finas ou
  configurações locais.
- Runtime, policy engine, audit, identity, approval, registry, guardrails, memória, A2A e
  supply chain não devem importar SDKs de provedores LLM diretamente.
- Integrações reais com LLMs devem ser implementadas por adapters atrás de interfaces ou
  protocolos estáveis.
- Provider, modelo e ferramenta de execução podem ser observados como metadados, mas não
  devem ser a base primária de autorização.

## Consequências

### Positivas

- Menor acoplamento a fornecedor.
- Migração mais simples entre provedores e modelos.
- Testes mais determinísticos, com mocks e adapters substituíveis.
- Menor risco de decisões de política ficarem presas a nomes comerciais.
- Melhor compatibilidade com Codex, Claude Code, Cursor, CI e outras ferramentas.

### Negativas

- Adapters adicionam uma camada de indireção.
- Recursos exclusivos de um provedor exigem extensão explícita do contrato comum.
- Configurações locais de ferramenta não são compartilhadas automaticamente pelo projeto.

## Alternativas consideradas

### Padronizar em uma única ferramenta

Rejeitado. Reduz variabilidade operacional no curto prazo, mas aumenta lock-in e
dificulta adoção por equipes com stacks diferentes.

### Manter instruções duplicadas por ferramenta

Rejeitado como fonte canônica. Duplicação tende a divergir. Arquivos específicos podem
existir apenas como ponte para `AGENTS.md`.

### Usar imports diretos de SDKs no domínio

Rejeitado. Isso mistura controle de governança com implementação de inferência e aumenta
o custo de troca de provedor.

## Implementação recomendada

Quando LLMs reais forem conectadas, use uma estrutura semelhante a:

```text
src/governance/llm/
  provider.py
  mock.py
  openai_adapter.py
  anthropic_adapter.py
  azure_adapter.py
  ollama_adapter.py
```

O domínio deve depender de abstrações como `LlmProvider`, `LlmRequest` e `LlmResponse`.
Adapters podem depender dos SDKs concretos.
