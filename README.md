# CNCS Security Feeds

Repositório público para manter indicadores de rede comunicados pelo Centro Nacional de Cibersegurança (CNCS). O feed principal é validado, normalizado, ordenado e não contém duplicados.

> **Aviso:** este projeto não é oficial nem é mantido pelo CNCS. A inclusão de um endereço no feed não constitui, por si só, prova de atividade maliciosa. Valide o impacto antes de aplicar bloqueios em produção.

## Feed disponível

| Feed | Conteúdo | URL raw |
| --- | --- | --- |
| `blacklist_cncs.txt` | IPv4, IPv6 e redes CIDR ativas | `https://raw.githubusercontent.com/joseeduardoalbuquerque/cncs-security-feeds/main/feeds/blacklist_cncs.txt` |

O ficheiro contém exclusivamente um indicador por linha, para ser consumido por firewalls, SIEM, SOAR, scripts e outros sistemas de segurança.

## Atualização manual no GitHub

1. Abra [`incoming/cncs.txt`](incoming/cncs.txt).
2. Selecione **Edit this file**.
3. Substitua os comentários pelos IPs ou CIDR recebidos, um por linha.
4. Grave diretamente na branch `main` ou crie um pull request.
5. Na branch `main`, a ação `Update CNCS feed` valida os dados, atualiza o histórico, regenera o feed e limpa o ficheiro de entrada.

Também pode abrir **Actions → Update CNCS feed → Run workflow** e indicar:

* `add` para ativar indicadores;
* `remove` para retirar indicadores;
* os indicadores, separados por linhas, espaços, vírgulas ou ponto e vírgula;
* uma referência pública e não confidencial, se aplicável.

## Atualização local

```bash
python scripts/manage_feed.py add \
  --input novos_ips.txt \
  --source-ref "CNCS notification"

python scripts/manage_feed.py remove \
  --input ips_a_remover.txt \
  --source-ref "CNCS withdrawal"

python scripts/manage_feed.py validate
```

Por defeito, apenas endereços globais são aceites. Se uma comunicação incluir deliberadamente endereços privados, reservados ou de documentação, use `--allow-non-global` depois de confirmar o conteúdo.

## Atualização automática

O workflow aceita o evento autenticado `repository_dispatch`, com o tipo `cncs_indicators_received`. Isto permite integrar uma caixa de correio, um SOAR, um webhook ou outra origem sem guardar credenciais no repositório público.

Consulte [Automação por API ou email](docs/AUTOMATION.md).

## Estrutura

```text
feeds/blacklist_cncs.txt       Feed limpo para consumo
data/cncs_indicators.json      Histórico e estado dos indicadores
incoming/cncs.txt              Caixa de entrada para atualização manual
scripts/manage_feed.py         Validação e gestão do feed
tests/                         Testes automatizados
.github/workflows/             Validação e atualização automática
```

## Regras de segurança

* Nunca publique o corpo integral de emails do CNCS, anexos, credenciais, dados pessoais ou informação de incidentes.
* Use referências genéricas ou identificadores que possam ser divulgados publicamente.
* Confirme falsos positivos antes de aplicar o feed em modo de bloqueio.
* Comece, sempre que possível, em modo de monitorização e promova depois para bloqueio.
* Remova indicadores quando exista comunicação de retirada ou quando deixarem de ser aplicáveis.

## Licença

O código deste repositório é disponibilizado sob a [licença MIT](LICENSE). Os indicadores mantêm a natureza e eventuais condições da respetiva fonte.
