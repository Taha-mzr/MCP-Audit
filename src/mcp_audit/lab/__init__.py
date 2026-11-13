"""The lab: dynamic tests of MCP servers in a locked-down container (rule sheet docs/rules/D1.md).

Three parts that do not know about each other's details:

- container.py starts any program in a closed container, prepares the fake files and reads them;
- probes.py says what to ask and how to judge the answer, for any file server;
- programs.py says, for each supported program and version, which tool reads and which writes.

d1.py puts them together for one server of the configuration.
"""
