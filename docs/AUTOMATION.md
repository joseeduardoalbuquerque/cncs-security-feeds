# Automação por API ou email

## API do GitHub

O evento `repository_dispatch` permite enviar indicadores para o workflow sem expor credenciais no repositório.

Exemplo de pedido:

```bash
curl --request POST \
  --url https://api.github.com/repos/joseeduardoalbuquerque/cncs-security-feeds/dispatches \
  --header "Accept: application/vnd.github+json" \
  --header "Authorization: Bearer $CNCS_FEED_GITHUB_TOKEN" \
  --header "X-GitHub-Api-Version: 2022-11-28" \
  --data '{
    "event_type": "cncs_indicators_received",
    "client_payload": {
      "operation": "add",
      "indicators": ["203.0.113.10", "2001:db8::10"],
      "source_ref": "CNCS notification",
      "observed_at": "2026-09-04T12:00:00Z",
      "allow_non_global": true
    }
  }'
```

Os endereços do exemplo pertencem a intervalos de documentação. Em produção, remova `allow_non_global` ou defina-o como `false`.

Use um token fine-grained com acesso apenas a este repositório e com a permissão mínima necessária para disparar o evento. Guarde-o exclusivamente no cofre de segredos da plataforma que envia o pedido.

## Integração com email

O GitHub Actions não lê diretamente uma caixa de correio. É necessário um componente autenticado entre o email e a API:

1. chega um email do remetente oficial previamente validado;
2. a automação extrai apenas IPv4, IPv6 e CIDR do corpo ou de um anexo autorizado;
3. apresenta ou aplica uma regra de aprovação, conforme o nível de risco;
4. envia um `repository_dispatch` para este repositório;
5. o workflow valida, normaliza, atualiza o histórico e publica o feed.

Pode implementar este fluxo com uma automação da caixa de correio, um SOAR ou uma pequena função serverless. A validação do remetente deve usar o endereço completo e, quando disponível, os resultados SPF, DKIM e DMARC. Não baseie a confiança apenas no nome apresentado.

## Payload

| Campo | Obrigatório | Valores | Finalidade |
| --- | --- | --- | --- |
| `operation` | Não | `add`, `remove` | Ativa ou retira indicadores |
| `indicators` | Sim | string ou lista | IPs e CIDR a processar |
| `source_ref` | Não | texto até 200 caracteres | Referência pública da origem |
| `observed_at` | Não | ISO 8601 com timezone | Momento da observação |
| `allow_non_global` | Não | booleano | Permite endereços não globais |

## Controlo recomendado

Para uma firewall de produção, a melhor política inicial é automatizar a ingestão e manter uma aprovação humana antes do bloqueio. Depois de medir falsos positivos, o processo pode evoluir para bloqueio automático de indicadores com elevada confiança.
