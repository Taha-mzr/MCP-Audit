# Le fichier de politique

| | |
|---|---|
| Statut de la fiche | en vigueur depuis le 2026-11-12 |
| Étape du plan | C-1 |
| Code | `src/mcp_audit/policy.py`, et C1 dans `checks.py` (étapes C-2 et C-3) |
| Tests | `tests/test_policy.py` |

## Choix de conception

| N° | Question | Choix | Pourquoi |
|---|---|---|---|
| 1 | Quel format de fichier ? | TOML, au lieu du YAML prévu dans le plan | Python sait déjà le lire, sans rien installer. Il accepte les commentaires `#`. Le YAML demande `pyyaml`, et sa fonction `yaml.load` peut lancer du code si on oublie `safe_load`. |
| 2 | Comment on désigne un programme ? | Par son nom dans la config, par exemple `maison` | C'est le nom que l'utilisateur voit déjà. Si deux applications ont un programme du même nom, la même règle vaut pour les deux. |
| 3 | Un dossier permis donne-t-il aussi les dossiers qu'il contient ? | Oui | Permettre `~/notes` permet `~/notes/cours`. Sinon il faudrait écrire chaque sous-dossier à la main. |
| 4 | Si la config donne un dossier plus large que la politique, quel statut ? | CONFIRMED | La politique dit ce que l'utilisateur voulait, la config dit ce qu'il a donné. Les deux viennent de lui, pas du programme, donc l'écart est sûr. |
| 5 | Où est le fichier ? | Seulement là où on le donne : `--policy fichier.toml` | Pas de recherche automatique. On sait toujours quelle politique a servi. |

## Pourquoi une politique

Aujourd'hui, C1 voit `/Users/jean` et dit TO REVIEW : il ne sait pas si jean voulait donner tout son dossier.
La politique est l'endroit où l'utilisateur l'écrit. Avec elle :

- C1 peut dire « ta config donne plus que ce que tu as permis » ;
- D1, le test dans Docker, sait ce qu'il a le droit de lancer, et ce que le programme devrait pouvoir lire ou écrire.

## Ce qu'elle contient

Une section par programme. Tous les champs sont **notre choix** : aucune norme ne décrit ce fichier.

| Champ | Sens | Obligatoire |
|---|---|---|
| `[servers.<nom>]` | le programme, par son nom dans la config | oui |
| `audit_authorized` | `true` si D1 a le droit de lancer ce programme dans Docker. Sinon D1 refuse | non, `false` par défaut |
| `read` | les dossiers que le programme peut lire | non, vide par défaut |
| `write` | les dossiers où il peut écrire. Écrire permet aussi de lire | non, vide par défaut |

On l'utilise avec `uv run mcp-audit audit --policy politique.toml`.

Un chemin s'écrit comme dans une config : `~/notes`, `/Users/jean/notes`, `C:/Users/jean/notes`.
Il est nettoyé comme dans C1 : majuscules, `\`, `..`, `~`.

## Exemple

```toml
# Ma politique pour mcp-audit

[servers.notes]
audit_authorized = true
read = ["~/notes"]
write = ["~/notes/brouillons"]

[servers.maison]
read = ["~/Documents/cours"]
```

Avec la config de `C1-flux.md` :

| Programme | Config | Politique | C1 dit |
|---|---|---|---|
| `notes` | `/Users/jean/notes` | lecture `~/notes` | passed |
| `maison` | `/Users/jean` | lecture `~/Documents/cours` | **CONFIRMED** : la config donne tout le dossier personnel, la politique seulement `~/Documents/cours` |
| `meteo` | une `url` | absent | not run, comme aujourd'hui |
| un programme absent de la politique | `/Users/jean` | absent | TO REVIEW, comme aujourd'hui |
| `maison` | `/Users/jean/photos` | lecture `~/Documents/cours` | **CONFIRMED**, gravité medium : ce dossier n'est pas dans la politique |

Seuls les arguments qui ressemblent à un chemin sont comparés : ils commencent par `/`, `~` ou une lettre de disque.
Pour comparer, `/Users/jean` est lu comme `~` : on suppose que le dossier personnel de la config est celui de l'utilisateur.

## Quand le fichier est mal écrit

L'outil s'arrête avec un message clair, et ne fait pas l'audit. Il ne devine jamais.

Les messages sont en anglais, comme le reste de l'outil.

| Erreur | Exemple | Message |
|---|---|---|
| Pas du TOML | `read = [~/notes` | la ligne de l'erreur |
| Champ inconnu | `lecture = [...]` | « champ inconnu `lecture` dans `servers.notes` » |
| Mauvais type | `audit_authorized = "oui"` | « `audit_authorized` doit être true ou false » |
| Chemin vide | `read = [""]` | « chemin vide dans `servers.notes.read` » |

Un champ inconnu est une erreur, pas un oubli silencieux : une faute de frappe dans `audit_authorized`
ne doit jamais faire croire que le test est permis, ou interdit.

## Limites

- La politique dit ce que l'utilisateur **veut**. Elle ne prouve rien sur ce que le programme **fait** : c'est le rôle de D1.
- Un programme permis par la politique n'est pas « sûr ». L'absence d'alerte n'est jamais une garantie.
- Si l'application envoie d'autres dossiers pendant que le programme tourne, par les Roots de MCP, la politique ne les voit pas.

## Sources

- [Documentation Python, `tomllib`](https://docs.python.org/3/library/tomllib.html), lue le 2026-11-12 :
  « Added in version 3.11 ». Le projet demande Python 3.12, donc rien à installer.
  « This module does not support writing TOML » : on lit seulement, c'est ce qu'il nous faut.
- [TOML v1.0.0](https://toml.io/en/v1.0.0), lu le 2026-11-12 :
  « A hash symbol marks the rest of the line as a comment, except when inside a string. »
- [Documentation PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation), lue le 2026-11-12 :
  « It is not safe to call `yaml.load` with any data received from an untrusted source! ».
  `yaml.safe_load` limite ce risque. La page est ancienne, avec des exemples en Python 2.
- `CLAUDE.md` du projet : « Tests dynamiques seulement avec `audit_authorized: true` dans la politique ».
- Fiche [C1](rules/C1.md) : le nettoyage des chemins.

## Historique

- 2026-11-12 : première version, avec ses tests et son code.
