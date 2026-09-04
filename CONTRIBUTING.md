# Contribuir

Aceitam-se correções ao código e propostas de indicadores através de pull request.

Antes de submeter:

1. não inclua dados pessoais, emails, anexos ou informação confidencial;
2. coloque apenas IPv4, IPv6 ou CIDR válidos em `incoming/cncs.txt`;
3. explique a origem e o motivo na descrição do pull request;
4. execute `python -m unittest discover -s tests -v` e `python scripts/manage_feed.py validate`.

Os indicadores propostos por terceiros devem ser confirmados antes de serem integrados.
