# <ID> : <nom court de la règle>

| | |
|---|---|
| Statut de la fiche | brouillon / validée par Taha le AAAA-MM-JJ |
| Code | `src/mcp_audit/checks.py`, fonction `check_<id>` |
| Tests | `tests/test_checks.py`, tests `test_<id>_...` |
| OWASP MCP Top 10 | MCPxx:2025, titre exact |
| CWE | CWE-xxx, titre exact |

## Ce qu'elle détecte

Une phrase. Ce que la règle regarde dans la config, et rien d'autre.

## Pourquoi c'est un risque

Ce qui peut arriver, avec un vrai cas : une CVE, un incident publié, ou une phrase d'une source officielle.

## Sources

Chaque source a son lien et la date où on l'a lue. Une phrase citée est entre guillemets.

- [Nom de la source](lien), lue le AAAA-MM-JJ : « citation courte ».

## La logique exacte

Ce que la règle fait, pas à pas, assez précis pour réécrire le code à partir de la fiche.
Si une liste est notre propre choix et ne vient pas d'une source, on l'écrit ici.

## Résultat et gravité

| Cas | Statut | Gravité | Pourquoi cette gravité |
|---|---|---|---|
| ... | CONFIRMED / TO REVIEW | critical / high / medium / low | ... |

Quand la règle ne s'applique pas, elle dit `not run` avec la raison.

## Exemples

Doit alerter :

```json
```

Ne doit pas alerter :

```json
```

Chaque exemple ici a un test du même nom.

## Ce que l'utilisateur doit faire

La correction à proposer dans le rapport, en une ou deux phrases.

## Limites

- Faux positifs connus : quand la règle alerte à tort.
- Faux négatifs connus : ce qu'elle ne voit pas.
- Ce qui demande le labo pour être prouvé.

## Comparaison avec les outils pros

Ce que font Cisco mcp-scanner et Snyk agent-scan sur ce point, d'après leur documentation.

## Historique

- AAAA-MM-JJ : création.
