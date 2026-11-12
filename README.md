# mcp-audit

[Français](README.fr.md)

`mcp-audit` finds the MCP servers configured on a machine and audits them, without starting
them. Each finding carries its evidence, a justified severity, OWASP MCP Top 10 and CWE
references, and a recommendation.

**Status: early development.** The static checks below work and are tested. The dynamic test in
a container (D1) is not built yet. Output and options may change.

## What it reads

The configuration files of Claude Desktop, Claude Code (user, project, local and managed
settings), Cursor, VS Code, GitHub Copilot, Gemini CLI, Codex and dev containers. Secret values
found in a configuration are never stored or shown: only their name, and `***`.

Not every way of adding an MCP server is read yet, for example Claude Desktop extensions. The
full list, with what is and is not covered, is in [docs/discovery.md](docs/discovery.md).

## The checks

| Check | What it looks for | Rule sheet |
|---|---|---|
| C1 | A local server given a folder broader than needed: the whole disk, a home folder, a folder of secrets such as `~/.ssh`, a folder where writing runs code such as `~/.claude`, a system folder. Also reads Docker and Podman mounts | [C1](docs/rules/C1.md) |
| C2 | A token or password written in clear in the configuration | to be written |
| C3 | A package started without a pinned version | to be written |
| C4 | A pinned version with a published advisory | to be written |
| C5 | A risky way of starting the server: through a shell, from a relative path, a `--privileged` container | to be written |

Each rule has a sheet with its sources, its exact logic, its examples and its limits.
[docs/coverage.md](docs/coverage.md) shows which of the ten OWASP MCP Top 10 risks are covered.

## Install and run

Requires Python 3.12 or later and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/Taha-mzr/MCP-Audit.git
cd MCP-Audit
uv run mcp-audit discover          # list the servers found
uv run mcp-audit audit             # run the checks on them
```

Other options:

```sh
uv run mcp-audit audit --config mcp.json             # audit one configuration file
uv run mcp-audit audit -- npx -y some-server /data   # audit one command
uv run mcp-audit audit --output report.json          # also write the JSON report
uv run mcp-audit audit --policy policy.toml          # compare with what you allow
```

## The policy file

Without a policy, `mcp-audit` cannot know which folders you meant to give, so a broad folder is
reported as **TO REVIEW**. A policy states it:

```toml
[servers.notes]
read = ["~/notes"]
write = ["~/notes/drafts"]
```

With it, a folder outside the policy is reported as **CONFIRMED**. A badly written policy stops
the audit with a clear message. Details: [docs/policy.md](docs/policy.md).

## What a report means

| Status | Meaning |
|---|---|
| CONFIRMED | The problem is certain, from evidence that does not come from the server itself |
| TO REVIEW | Something to check: it depends on your intent or on the server's code |
| passed | No problem was observed for what this check looks at |
| not run | The check does not apply, with the reason |

A check with no finding means that no problem was observed **for the probes listed**. It does
not mean the server is secure. What a server says about its own tools is recorded as a
declaration, never as a restriction.

## Authorized use only

The planned dynamic test will start MCP servers and probe what they can actually reach. It will
run only in a disposable container, on fictitious data, and only for servers marked
`audit_authorized = true` in your policy. Use it only on servers and machines you own or are
explicitly authorized to audit.

## License

Apache License 2.0, see [LICENSE](LICENSE).
