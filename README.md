# mcp-audit

[Français](README.fr.md)

`mcp-audit` audits the MCP servers declared in a Claude Desktop or Claude Code configuration
against a policy that states the access you expect. Each finding carries its evidence, a
justified severity and a recommendation.

**Status: under construction.** Nothing here is usable yet. The scope, the checks and their
limits will be documented as they are built.

## Authorized use only

Dynamic checks start MCP servers and probe what they can actually reach. Run them only on
servers and machines you own or are explicitly authorized to audit. They run in a disposable,
network-less container on fictitious data, never on your real files.

## What a report means

A check with no finding means that no problem was observed **for the probes listed**. It does
not mean the server is secure. Tool descriptions and annotations are recorded as declarations,
never as enforced restrictions.

## License

Apache License 2.0, see [LICENSE](LICENSE).
