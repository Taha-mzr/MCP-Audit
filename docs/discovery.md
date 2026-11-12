# La découverte : toutes les façons d'ajouter un programme MCP

Pour chaque application, ce tableau liste **chaque façon** d'ajouter un programme MCP, d'après la doc
officielle lue le 2026-11-09, et dit si notre outil la voit.

- **oui** : `mcp-audit discover` lit l'endroit où c'est rangé.
- **non** : le programme peut tourner sur la machine, mais l'outil ne le voit pas. C'est un trou.
- **cloud** : le programme tourne chez l'éditeur, pas sur la machine. Il n'y a rien à lire sur le disque.
  C'est hors de notre outil.
- **non vérifié** : la doc lue ne dit pas où c'est rangé. On ne devine pas.

**Les fichiers d'un projet**, comme `.mcp.json` ou `.cursor/mcp.json`, sont lus dans le dossier où
on lance la commande, et dans chaque dossier de projet que `~/.claude.json` connaît.
Un projet qu'aucune de ces deux règles n'atteint n'est pas lu.

Quand une case dit « résumé », la phrase vient d'un résumé de la page et pas du texte exact.
Elle doit être relue avant d'écrire du code dessus.

## Claude Desktop

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| Éditer le fichier de config, par Réglages, Développeur, « Edit Config » | macOS `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows `%APPDATA%\Claude\claude_desktop_config.json`, Linux `~/.config/Claude/claude_desktop_config.json`, clé `mcpServers` | oui | [modelcontextprotocol.io](https://modelcontextprotocol.io/docs/develop/connect-local-servers) |
| Installer une extension depuis le catalogue de Claude | non indiqué | **non** | [support.claude.com](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop) |
| Installer un fichier `.mcpb` à la main, ou le glisser dans les réglages | non indiqué | **non** | même page, et [anthropic.com](https://www.anthropic.com/engineering/desktop-extensions) |
| Extensions installées par l'administrateur, par MDM sur Mac ou GPO sur Windows | non indiqué, page entreprise non lue | **non vérifié** | [anthropic.com](https://www.anthropic.com/engineering/desktop-extensions) |
| Plugin qui contient des programmes MCP locaux | non indiqué | **non vérifié** | [support.claude.com](https://support.claude.com/en/articles/11725091-when-to-use-desktop-and-web-connectors) |
| Connecteur personnalisé, par Customize, Connectors | dans le compte Claude | cloud | [support.claude.com](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) |
| Connecteur ajouté par l'organisation | dans le compte Claude | cloud | même page |

## Claude Code

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| `claude mcp add`, portée « local », celle par défaut | `~/.claude.json`, sous le chemin de chaque projet | oui, pour tous les projets | [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp) |
| `claude mcp add --scope user` | `~/.claude.json` | oui | même page, résumé |
| `claude mcp add --scope project`, ou éditer le fichier | `.mcp.json` à la racine du projet, clé `mcpServers` | oui | même page |
| `claude mcp add-json` | un des trois fichiers ci-dessus | oui | même page, résumé |
| `claude mcp add-from-claude-desktop` | copie dans `~/.claude.json` | oui | même page, résumé |
| Plugin qui contient des programmes MCP | `~/.claude/plugins`, dans `.mcp.json` ou `.claude-plugin/plugin.json` du plugin | **non** | [plugins-reference](https://code.claude.com/docs/en/plugins-reference) |
| Fichier géré par l'entreprise `managed-mcp.json` | macOS `/Library/Application Support/ClaudeCode/managed-mcp.json`, Linux `/etc/claude-code/managed-mcp.json`, Windows `C:\Program Files\ClaudeCode\managed-mcp.json`, clé `mcpServers` | oui | [managed-mcp](https://code.claude.com/docs/en/managed-mcp) |
| Clé `managedMcpServers` des réglages gérés | fichier de réglages gérés, chemin non lu. Programmes distants seulement | **non vérifié** | même page |
| Option `--mcp-config` au lancement | un fichier donné à la main, pour une session | **non** : à lire avec `mcp-audit --config` | même page |
| Connecteurs de claude.ai, chargés tout seuls | dans le compte Claude | cloud | [code.claude.com/docs/en/mcp](https://code.claude.com/docs/en/mcp), résumé |

## Cursor

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| Fichier du projet | `.cursor/mcp.json`, clé `mcpServers` | oui | [cursor.com/docs/mcp](https://cursor.com/docs/mcp) |
| Fichier global | `~/.cursor/mcp.json`, clé `mcpServers` | oui | même page |
| Bouton « Add New MCP Server » des réglages | non indiqué, ancienne doc seulement | **non vérifié** | [docs.cursor.com](https://docs.cursor.com/context/model-context-protocol) |
| Bouton « Add to Cursor » du catalogue | non indiqué | **non vérifié** | [cursor.com/docs/mcp](https://cursor.com/docs/mcp) |
| Une extension qui appelle `vscode.cursor.mcp.registerServer()` | dans le code de l'extension | **non** | même page |
| Catalogue d'équipe | non indiqué | **non vérifié** | même page |
| Programmes d'équipe pour les agents dans le cloud | chez Cursor | cloud | même page |

## VS Code avec GitHub Copilot

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| Fichier de l'espace de travail | `.vscode/mcp.json`, clé `servers` | oui | [mcp-configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| Fichier `.mcp.json` à la racine du projet, réglage expérimental | `.mcp.json`, clé `mcpServers` | oui, c'est le même fichier que Claude Code | [mcp-servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |
| Fichier `mcp.json` du profil utilisateur | chemin non donné dans les pages lues | **non** | [mcp-configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| Fichier global de Copilot | `$COPILOT_HOME/mcp-config.json`, sinon `~/.copilot/mcp-config.json` | oui | [mcp-servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |
| Commande « MCP: Add Server » | écrit dans un des fichiers ci-dessus, au choix | en partie : pas le profil utilisateur | même page |
| `code --add-mcp` en ligne de commande | profil utilisateur | **non** | [mcp-configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration), résumé |
| Conteneur de développement | `devcontainer.json`, clés `customizations`, `vscode`, `mcp`, `servers`. Le fichier est cherché dans `.devcontainer/devcontainer.json`, `.devcontainer.json` et `.devcontainer/<dossier>/devcontainer.json`, d'après la [spécification des conteneurs](https://containers.dev/implementors/spec/) | oui | [manage-mcp-servers](https://code.visualstudio.com/docs/agents/run/manage-mcp-servers) |
| Bouton « Install » du catalogue | non indiqué | **non vérifié** | [mcp-servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |
| Plugin d'agent qui contient des programmes MCP | non indiqué | **non vérifié** | même page |
| Extension qui déclare des programmes par l'API de VS Code | dans le code de l'extension | **non** | [mcp-configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration) |
| Lire les programmes d'une autre application, comme Claude Desktop ou Cursor | les fichiers de ces applications | oui pour ceux qu'on lit déjà | même page, résumé |
| Connecteurs Copilot gérés par GitHub | chez GitHub | cloud | [mcp-servers](https://code.visualstudio.com/docs/agent-customization/mcp-servers) |

## Windsurf

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| Fichier de config | `~/.codeium/windsurf/mcp_config.json` d'après la doc de VS Code, pas celle de Windsurf | **non** | la page de Windsurf redirige vers un autre site : **non lue** |

## GitHub Copilot CLI

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| `/mcp add`, `copilot mcp add`, ou éditer le fichier | `~/.copilot/mcp-config.json`, clé `mcpServers` | oui | [add-mcp-servers](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers), résumé |
| Variable `COPILOT_HOME` | déplace le dossier `.copilot` | oui | [configure-copilot-cli](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/configure-copilot-cli), résumé |
| Fichier du dépôt `.mcp.json` | `.mcp.json`, du dossier courant jusqu'à la racine du dépôt | en partie : seulement le dossier courant | [add-mcp-servers](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-mcp-servers), résumé |
| Fichier du dépôt `.github/mcp.json` | `.github/mcp.json` | **non** | même page, résumé |
| `/mcp search` dans le registre GitHub | même fichier que `/mcp add` | oui | même page, résumé |
| Agent Copilot sur GitHub, dans les réglages du dépôt | chez GitHub | cloud | [configure-mcp-servers](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/configure-mcp-servers), résumé |

## Gemini CLI

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| Fichier utilisateur | `~/.gemini/settings.json`, clé `mcpServers` | oui | [geminicli.com](https://geminicli.com/docs/cli/configuration/) |
| Fichier du projet | `.gemini/settings.json` | oui | même page |
| `gemini mcp add` | un des deux fichiers ci-dessus | oui | [mcp-server.md](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md), résumé |
| Fichier système de l'administrateur | Linux `/etc/gemini-cli/settings.json`, Windows `C:\ProgramData\gemini-cli\settings.json`, macOS `/Library/Application Support/GeminiCli/settings.json`, ou `GEMINI_CLI_SYSTEM_SETTINGS_PATH` | oui | [geminicli.com](https://geminicli.com/docs/cli/configuration/) |
| Extensions Gemini | non lu | **non vérifié** | doc des extensions non lue |

## Codex : application, ligne de commande, extension d'éditeur

| Façon | Où c'est rangé | L'outil le voit ? | Source |
|---|---|---|---|
| Fichier utilisateur, aussi rempli par Réglages, MCP servers, dans l'application | `~/.codex/config.toml`, tables `[mcp_servers.<nom>]` | oui | [learn.chatgpt.com MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), résumé |
| Fichier du projet, lu seulement si le projet est approuvé | `.codex/config.toml` | oui | [config-reference](https://learn.chatgpt.com/docs/config-file/config-reference), résumé |
| Variable `CODEX_HOME` | déplace le dossier de config | **non** : on lit toujours `~/.codex` | même page, résumé |
| Profils | `$CODEX_HOME/<nom>.config.toml` | **non vérifié** : la doc ne dit pas s'ils peuvent contenir des programmes | même page, résumé |
| Plugins qui contiennent des programmes MCP | non indiqué | **non vérifié** | [learn.chatgpt.com MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), résumé |

## Bilan

**Façons à regarder sur la machine : 47.** Les 6 façons « cloud » sont comptées à part.

| | Nombre |
|---|---|
| L'outil les voit | 25, dont 2 en partie |
| L'outil ne les voit pas | 11 |
| Non vérifié | 11 |
| Dans le cloud, hors outil | 6, en plus des 47 |

Attention, ce compte gonfle les « oui » : plusieurs façons écrivent dans le même fichier.
Par exemple `claude mcp add-json` et `claude mcp add` écrivent tous deux dans `~/.claude.json`.
Le bon chiffre à retenir : **l'outil lit 14 emplacements différents.**

### Ajouté le 2026-11-09, après relecture du texte exact de la doc

- `managed-mcp.json` de Claude Code, aux trois chemins donnés.
- Le fichier système de Gemini CLI, aux trois chemins donnés, et sa variable.
- Les programmes déclarés dans `devcontainer.json`.
- Les programmes locaux de tous les projets de `~/.claude.json`, plus les fichiers de ces projets.

### Pas encore ajouté : la doc n'a été lue qu'en résumé

- `.github/mcp.json` et `.mcp.json` des dossiers parents, pour Copilot CLI.
- La variable `CODEX_HOME` : la doc lue ne donne pas sa valeur par défaut.
- Les plugins de Claude Code, dans `~/.claude/plugins` : l'organisation des dossiers n'est pas claire.

### Programmes désactivés : pas encore géré

Claude Code permet de désactiver un programme, avec les réglages `disabledMcpServers` et
`disabledMcpjsonServers`. Un programme de `.mcp.json` doit aussi être approuvé avant de tourner.
L'outil ne lit pas encore ces réglages : il présente tous les programmes comme actifs.

### À vérifier avant de coder : l'emplacement n'est pas dans la doc lue

- Les extensions de Claude Desktop, celles du catalogue et les fichiers `.mcpb`.
- Le profil utilisateur de VS Code, la page des profils n'a pas été lue.
- Windsurf, sa page n'a pas pu être lue.
- Les plugins et extensions de Codex, Gemini et VS Code.
- Peut-être oubliés, à vérifier : l'ancienne clé `"mcp"` dans `settings.json` de VS Code, les
  programmes déclarés dans les sous-agents de Claude Code, VS Code Insiders et VSCodium.

Pour ces cas, la méthode est : lire la page de doc qui manque. Si elle ne dit rien, regarder sur le Mac
de Taha, avec une commande qui ne fait que lister des noms de fichiers.
