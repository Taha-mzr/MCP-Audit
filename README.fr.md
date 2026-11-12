# mcp-audit

[English](README.md)

`mcp-audit` trouve les serveurs MCP configurés sur une machine et les audite, sans les lancer.
Chaque constat est accompagné de sa preuve, d'une gravité justifiée, des références OWASP MCP
Top 10 et CWE, et d'une recommandation.

**État : en développement.** Les contrôles statiques ci-dessous fonctionnent et sont testés. Le
test dynamique dans un conteneur (D1) n'est pas encore construit. Les sorties et les options
peuvent changer.

## Ce qu'il lit

Les fichiers de configuration de Claude Desktop, Claude Code (réglages utilisateur, projet,
locaux et gérés par l'administrateur), Cursor, VS Code, GitHub Copilot, Gemini CLI, Codex et
des dev containers. Les valeurs secrètes trouvées dans une configuration ne sont jamais
gardées ni affichées : seulement leur nom, et `***`.

Toutes les façons d'ajouter un serveur MCP ne sont pas encore lues, par exemple les extensions
de Claude Desktop. La liste complète, avec ce qui est couvert ou non, est dans
[docs/discovery.md](docs/discovery.md).

## Les contrôles

| Contrôle | Ce qu'il cherche | Fiche |
|---|---|---|
| C1 | Un serveur local à qui on donne un dossier plus large que nécessaire : le disque entier, un dossier personnel, un dossier de secrets comme `~/.ssh`, un dossier où écrire lance du code comme `~/.claude`, un dossier système. Lit aussi les montages Docker et Podman | [C1](docs/rules/C1.md) |
| C2 | Un token ou un mot de passe écrit en clair dans la configuration | à écrire |
| C3 | Un paquet lancé sans version fixée | à écrire |
| C4 | Une version fixée qui a une faille publiée | à écrire |
| C5 | Un lancement risqué : par un shell, par un chemin relatif, un conteneur `--privileged` | à écrire |

Chaque règle a une fiche avec ses sources, sa logique exacte, ses exemples et ses limites.
[docs/coverage.md](docs/coverage.md) montre lesquels des dix risques de l'OWASP MCP Top 10
sont couverts.

## Installer et lancer

Il faut Python 3.12 ou plus et [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/Taha-mzr/MCP-Audit.git
cd MCP-Audit
uv run mcp-audit discover          # lister les serveurs trouvés
uv run mcp-audit audit             # les auditer
```

Autres options :

```sh
uv run mcp-audit audit --config mcp.json             # auditer un seul fichier de configuration
uv run mcp-audit audit -- npx -y un-serveur /data    # auditer une seule commande
uv run mcp-audit audit --output rapport.json         # écrire aussi le rapport JSON
uv run mcp-audit audit --policy politique.toml       # comparer avec ce que vous permettez
```

## Le fichier de politique

Sans politique, `mcp-audit` ne peut pas savoir quels dossiers vous vouliez donner : un dossier
large est donc signalé **TO REVIEW**. Une politique le dit :

```toml
[servers.notes]
read = ["~/notes"]
write = ["~/notes/brouillons"]
```

Avec elle, un dossier hors de la politique est signalé **CONFIRMED**. Une politique mal écrite
arrête l'audit avec un message clair. Détails : [docs/policy.md](docs/policy.md).

## Ce que signifie un rapport

| Statut | Sens |
|---|---|
| CONFIRMED | Le problème est sûr, d'après une preuve qui ne vient pas du serveur lui-même |
| TO REVIEW | À vérifier : cela dépend de votre intention ou du code du serveur |
| passed | Aucun problème observé pour ce que ce contrôle regarde |
| not run | Le contrôle ne s'applique pas, avec la raison |

Un contrôle sans constat signifie qu'aucun problème n'a été observé **pour les sondes
listées**. Cela ne signifie pas que le serveur est sûr. Ce qu'un serveur dit de ses propres
outils est enregistré comme une déclaration, jamais comme une restriction.

## Usage autorisé uniquement

Le test dynamique prévu lancera des serveurs MCP et vérifiera ce qu'ils peuvent réellement
atteindre. Il tournera seulement dans un conteneur jetable, sur des données fictives, et
seulement pour les serveurs marqués `audit_authorized = true` dans votre politique. Ne
l'utilisez que sur des serveurs et des machines que vous possédez ou que vous êtes
explicitement autorisé à auditer.

## Licence

Apache License 2.0, voir [LICENSE](LICENSE).
