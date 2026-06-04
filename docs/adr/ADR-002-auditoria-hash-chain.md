# ADR-002 — Auditoria com Hash Chain (JSONL append-only)

**Status:** Aceito  
**Data:** 2025-06-01  
**Autores:** Time de Plataforma de IA

---

## Contexto

Precisávamos de um mecanismo de auditoria que:

1. Registrasse toda ação de agentes
2. Fosse resistente a adulteração retroativa
3. Fosse legível sem ferramentas especializadas
4. Funcionasse offline e sem dependências externas

As alternativas consideradas foram:

1. **Log estruturado simples (JSONL)**: sem proteção contra adulteração
2. **Banco de dados relacional com auditoria**: requer infra, mutável
3. **Blockchain permissionada**: complexidade alta, dependência de serviço
4. **JSONL com hash chain** (escolhido): verificável, sem dependências externas
5. **WORM storage (S3 Object Lock)**: ótimo para produção, mas requer infra

## Decisão

Adotamos **JSONL append-only com hash chain SHA-256** como mecanismo de auditoria.

## Motivação

O hash chain cria uma estrutura de dados similar ao Merkle chain de uma blockchain,
mas sem a complexidade de consenso distribuído. A verificação é O(n) e determinística.

### Propriedades garantidas

- **Detecção de adulteração**: qualquer modificação de uma entrada invalida toda
  a cadeia subsequente
- **Detecção de inserção**: uma entrada inserida quebraria o `previous_hash`
- **Detecção de deleção**: sequências numéricas permitem detectar linhas removidas
- **Sem dependências**: `hashlib` é stdlib Python; nenhum pacote externo necessário

### Limitações conhecidas

- **Não impede** adulteração em tempo real (durante a escrita)
- **Não impede** que um atacante recalcule toda a cadeia do zero
- **Não é distribuída**: uma única cópia do log pode ser destruída

## Consequências

**Positivas:**
- `verify_chain()` detecta adulteração com 100% de certeza em O(n)
- Formato legível por humanos e processável com `jq`
- Replay trivial: releia o arquivo em ordem

**Negativas / Limitações:**
- Um atacante com acesso irrestrito ao disco pode recriar toda a cadeia
- Não há garantia de **confidencialidade** — apenas **integridade**

## Ponto de extensão para produção

Para auditoria regulatória séria, combine o hash chain com:

1. **Assinatura assimétrica (Ed25519)**: cada entrada assinada com chave privada
   em HSM → atacante não pode recriar a cadeia sem a chave privada
2. **WORM storage**: S3 Object Lock ou Azure Blob imutável previne deleção
3. **Timestamp externo**: ancoragem em RFC 3161 TSA ou blockchain pública
   para provar a ordem temporal de forma independente

O hash chain deste repositório é o **ponto de partida** para estas extensões,
não o destino final.
