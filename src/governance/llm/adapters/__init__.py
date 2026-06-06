"""
Adapters de provedores de LLM reais.

Cada adapter implementa o protocolo `LlmProvider` e importa o SDK do fornecedor
**preguiçosamente**, dentro do método que o utiliza. Assim, instalar o
repositório e rodar os testes/exemplos permanece offline e sem dependências de
fornecedor; só quem realmente usa um provedor precisa instalar o extra
correspondente (ex.: `pip install 'agentic-governance[anthropic]'`).

Para testes de conformidade sem rede, um cliente já construído pode ser injetado
via o parâmetro `client=...` de cada adapter.
"""

from __future__ import annotations

from governance.llm.adapters.anthropic_adapter import AnthropicAdapter
from governance.llm.adapters.azure_adapter import AzureOpenAIAdapter
from governance.llm.adapters.ollama_adapter import OllamaAdapter
from governance.llm.adapters.openai_adapter import OpenAIAdapter

__all__ = [
    "AnthropicAdapter",
    "AzureOpenAIAdapter",
    "OllamaAdapter",
    "OpenAIAdapter",
]
