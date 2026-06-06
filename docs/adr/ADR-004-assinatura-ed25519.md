# ADR-004: Assinatura Ed25519 no Audit Log

**Status:** Aceito  
**Data:** 2026-06-04  
**Autores:** Time de Plataforma de IA

---

## Contexto

O ADR-002 adotou hash chain SHA-256 para detectar adulteração do audit log.
Identificamos uma lacuna: um atacante com acesso ao disco pode **recriar toda a cadeia**
calculando novos hashes, tornando a adulteração indetectável pela verificação de chain.

## Decisão

Adotamos **assinatura Ed25519 em cada entrada** do audit log, implementada em
`src/governance/signing/signer.py` como `SignedAuditLogger` (extensão de `AuditLogger`).

## Motivação

### Por que Ed25519?

| Critério | RSA-2048 | ECDSA P-256 | Ed25519 (escolhido) |
|---------|----------|-------------|---------------------|
| Tamanho da assinatura | 256 bytes | 64 bytes | **64 bytes** |
| Velocidade de assinatura | Lento | Médio | **Muito rápido** |
| Resistência a timing attacks | Fraca | Média | **Forte** (determinístico) |
| Curva de implementação | Complexa | Média | **Simples** |
| Suporte em KMS/HSM | Sim | Sim | **Sim** |

Ed25519 é determinístico (sem nonce aleatório), resistente a side-channel attacks
e amplamente suportado por HSMs (AWS KMS, GCP KMS, Vault Transit).

### Não resolve tudo

- **Sem chave no HSM**: quem tem acesso à chave privada pode forjar assinaturas.
  Em produção, a chave privada NUNCA deve ficar em disco.
- **Não garante confidencialidade**: apenas integridade e autenticidade.
- **Não é WORM storage**: o arquivo ainda pode ser deletado.

## Consequências

**Positivas:**
- Forjamento retroativo exige a chave privada (mantida no HSM em produção)
- Chave pública pode ser distribuída a auditores externos
- `verify_signatures()` detecta adulteração mesmo sem acesso ao log original

**Negativas / Limitações:**
- `SignedAuditLogger` re-escreve a última linha ao adicionar a assinatura (I/O extra)
- Requer gestão do ciclo de vida da chave (rotação, backup)
- Em dev/test, usa chave em memória (sem persistência entre execuções)

## Ponto de extensão para produção

```python
# Em vez de AuditSigner.generate(), usar a KMS:
import boto3
kms = boto3.client("kms")

class KMSAuditSigner(AuditSigner):
    def sign_entry(self, event):
        payload = json.dumps(event.model_dump(...), ...)
        resp = kms.sign(KeyId="arn:aws:kms:...", Message=payload, SigningAlgorithm="ED25519")
        return base64.b64encode(resp["Signature"]).decode()
```
