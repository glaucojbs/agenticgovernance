# Exemplos de política em Rego (OPA)

Este diretório contém as mesmas regras do arquivo `example-readonly-agent.yaml`
reimplementadas em **Rego**, a linguagem do [Open Policy Agent (OPA)](https://www.openpolicyagent.org/).

Os arquivos Rego aqui são **ilustrativos** — não são executados pelo runtime
deste repositório, que usa o motor YAML nativo por simplicidade.

## Quando vale a pena adotar OPA ou Cedar em produção?

| Critério | Motor YAML (este repo) | OPA/Rego | AWS Cedar |
|----------|----------------------|----------|-----------|
| **Curva de aprendizado** | Baixa | Média | Média |
| **Expressividade** | Condições básicas | Alta (datalog-like) | Alta (estruturada) |
| **Performance** | Adequada para <1k req/s | Alta (compiled Wasm) | Alta (Rust) |
| **Auditoria de política** | Diff de YAML | `opa check`, `opa test` | `cedar validate` |
| **Integração com ecossistema** | Simples | Kubernetes, Envoy, Terraform | AWS IAM, Verified Permissions |
| **Verificação formal** | Não | Parcial (rego-test) | Sim (provably correct) |

**Recomendação**: use o motor YAML deste repositório para PoC e ambientes pequenos.
Migre para OPA quando precisar de:
- Políticas com lógica complexa (joins, negação, recursão)
- Performance acima de 1.000 avaliações/segundo
- Integração com Kubernetes (OPA Gatekeeper) ou service mesh (Envoy ext_authz)

Migre para Cedar quando:
- Você estiver no ecossistema AWS
- Precisar de verificação formal de políticas (provar que uma política nunca
  permite X, mesmo com inputs adversariais)
