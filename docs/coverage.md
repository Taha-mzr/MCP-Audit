# Couverture de l'OWASP MCP Top 10

Pour chacun des 10 risques, ce tableau dit ce que l'outil couvre aujourd'hui, et comment.

- Source : [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), lue le 2026-11-09.
  Le site affiche « version [v0.1] » et dit être en « Phase 3 – Beta Release ».
  Les identifiants finissent par `:2025`.
- Ce tableau change à chaque règle ajoutée ou corrigée. Il dit la vérité sur ce qui **manque**.

| Risque OWASP | Titre exact | Ce qu'on a | État |
|---|---|---|---|
| MCP01:2025 | Token Mismanagement & Secret Exposure | C2 : secret écrit en clair dans `env`, `headers` ou `args` | en partie : C2 ne regarde pas encore un secret dans une `url`, ni dans un fichier d'environnement à côté |
| MCP02:2025 | Privilege Escalation via Scope Creep | C1 : dossier trop large dans `args`. C5 : dossier trop large monté dans Docker | en partie : la config montre l'accès donné, le labo devra prouver l'accès réel |
| MCP03:2025 | Tool Poisoning | rien | **manque** : demande la liste des outils, donc le labo |
| MCP04:2025 | Software Supply Chain Attacks & Dependency Tampering | C3 : version pas fixée. C4 : version avec une faille connue | en partie : C4 ne connaît qu'un paquet, à remplacer par OSV.dev |
| MCP05:2025 | Command Injection & Execution | C5 regarde le lancement (`sh -c`, Docker `--privileged`, chemin `./`) | **mal étiqueté** : C5 n'est pas de l'injection, à revoir |
| MCP06:2025 | Prompt Injection via Contextual Payloads. La liste de la page d'accueil l'appelle « Intent Flow Subversion » | rien | labo |
| MCP07:2025 | Insufficient Authentication & Authorization | rien | **manque** : la config d'un programme distant le montre en partie, par exemple `http://` sans en-tête d'authentification |
| MCP08:2025 | Lack of Audit and Telemetry | rien | hors outil : cela dépend de l'application, pas de la config du programme |
| MCP09:2025 | Shadow MCP Servers | la découverte liste les programmes écrits dans les fichiers de config | en partie : 11 façons d'ajouter un programme ne sont pas lues, et 11 n'ont pas pu être vérifiées. Voir `docs/discovery.md` |
| MCP10:2025 | Context Injection & Over-Sharing | rien | labo |

## Ce qu'on corrige, dans l'ordre

1. C1 : fiche, puis tests et code.
2. C2, C3, C4, C5 : une fiche chacun, même méthode.
3. Nouvelle règle pour MCP07, sur les programmes distants.
4. C4 branché sur une copie locale de la base OSV.dev.
