# mcp-audit

[English](README.md)

`mcp-audit` audite les serveurs MCP déclarés dans une configuration Claude Desktop ou Claude
Code, par rapport à une politique qui décrit les accès attendus. Chaque constat est accompagné
de sa preuve, d'une gravité justifiée et d'une recommandation.

**État : en construction.** Rien n'est encore utilisable. Le périmètre, les contrôles et leurs
limites seront documentés au fur et à mesure.

## Usage autorisé uniquement

Les contrôles dynamiques lancent des serveurs MCP et vérifient ce qu'ils peuvent réellement
atteindre. Ne les exécute que sur des serveurs et des machines que tu possèdes ou que tu es
explicitement autorisé à auditer. Ils tournent dans un conteneur jetable, sans réseau, sur des
données fictives, jamais sur tes vrais fichiers.

## Ce que signifie un rapport

Un contrôle sans constat signifie qu'aucun problème n'a été observé **pour les sondes listées**.
Cela ne signifie pas que le serveur est sûr. Les descriptions et annotations des outils sont
enregistrées comme des déclarations, jamais comme des restrictions appliquées.

## Licence

Apache License 2.0, voir [LICENSE](LICENSE).
