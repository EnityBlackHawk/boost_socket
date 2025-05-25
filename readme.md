## Handshake

| Emissor  | Sentido | Receptor | Conteúdo                          |
|:---------|:-------:|:---------|:----------------------------------|
| Cliente  |    →    | Servidor | Certificado junto a chava publica |
| Servidor |    →    | Cliente  | Certificado junto a chave publica |  
| Cliente  |    →    | Servidor | Chave e vetor de inicializacao    |

### Certificado:
O certificado é em formato JSON:
```json
{
  "subject": "Alice@example.com",
  "issuer": "MyCA",
  "valid_from": "2025-01-01T00:00:00Z",
  "valid_to": "2026-01-01T00:00:00Z",
  "public_key": "<chave-publica>",
  "signature": "<assinatura em base 64>"
}
```

## Mensagens

As mensagem são sempre divididas em 4 pacotes:

| Conteúdo                          | Tamanho (bytes) |
|-----------------------------------|:---------------:|
| Tamanho da mensagem criptografada |       32        |
| Mensagem criptografada            |    Varivavel    |
| Tamanho do Hash + assinatura      |       32        |
| Hash + assinatura                 | 288 (32 + 256)  |
