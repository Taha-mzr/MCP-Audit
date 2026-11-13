"""A minimal MCP client over stdio, written for the lab (docs/rules/D1.md, "Le protocole").

Why not the official SDK: it validates every answer against the current schema, and refuses the
tool list of older servers (server-filesystem 2025.3.28 sends input schemas without "type").
An audit tool must talk to old and faulty servers, so this client checks only what it needs:
JSON-RPC 2.0 messages, one per line, with a size limit and a time limit on each request.

Everything the server sends is data. Nothing it sends is executed or shown without cleaning.
"""

from __future__ import annotations

import json
import queue
import subprocess  # noqa: S404 - only to run the docker CLI, always with a list of arguments
import threading
from dataclasses import dataclass
from typing import Any

from mcp_audit import __version__

# The client starts with the classic handshake, which servers of 2025 expect:
# https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle (read 2026-11-13).
PROTOCOL_VERSION = "2025-06-18"
MAX_LINE = 1_000_000  # bytes; a longer line is dropped, never parsed
CLOSE_TIMEOUT = 5  # seconds


class ClientError(RuntimeError):
    """The server did not answer in time, closed, or answered with a JSON-RPC error."""


@dataclass
class ToolResult:
    text: str  # every text item of the content, joined
    is_error: bool


class StdioClient:
    """Talks to one MCP server started from a list of arguments. Use it with `with`."""

    def __init__(self, args: list[str], env: dict[str, str]) -> None:
        self.args = args
        self.env = env
        self._process: subprocess.Popen[bytes] | None = None
        self._messages: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._next_id = 0

    def __enter__(self) -> StdioClient:
        self._process = subprocess.Popen(  # noqa: S603 - a list of arguments, no shell
            self.args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=self.env,
        )
        threading.Thread(target=self._read, daemon=True).start()
        return self

    def __exit__(self, *exc: object) -> None:
        process = self._process
        if process is None:
            return
        try:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=CLOSE_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(timeout=CLOSE_TIMEOUT)

    def _read(self) -> None:
        """Runs in a thread: one JSON object per line goes to the queue, None at the end."""
        if self._process is None or self._process.stdout is None:
            return
        stream = self._process.stdout
        while True:
            line = stream.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE:
                while line and not line.endswith(b"\n"):  # drop the rest of the long line
                    line = stream.readline(MAX_LINE + 1)
                continue
            try:
                message = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue  # the spec forbids it on stdout; ignore rather than trust it
            if isinstance(message, dict):
                self._messages.put(message)
        self._messages.put(None)

    def _send(self, message: dict[str, Any]) -> None:
        if self._process is None or self._process.stdin is None:
            raise ClientError("the server is not started")
        try:
            self._process.stdin.write(json.dumps(message).encode() + b"\n")
            self._process.stdin.flush()
        except OSError as error:
            raise ClientError("the server closed its input") from error

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    def request(self, method: str, params: dict[str, Any], timeout: float) -> dict[str, Any]:
        self._next_id += 1
        wanted = self._next_id
        self._send({"jsonrpc": "2.0", "id": wanted, "method": method, "params": params})
        while True:
            try:
                message = self._messages.get(timeout=timeout)
            except queue.Empty as error:
                raise ClientError(f"no answer to {method} after {timeout} s") from error
            if message is None:
                raise ClientError(f"the server stopped before answering {method}")
            if "method" in message:  # a request or notification from the server
                if "id" in message:
                    self._send({"jsonrpc": "2.0", "id": message["id"],
                                "error": {"code": -32601, "message": "not supported"}})  # fmt: skip
                continue
            if message.get("id") != wanted:
                continue
            if "error" in message:
                error = message["error"]
                text = error.get("message", "") if isinstance(error, dict) else ""
                raise ClientError(f"{method} returned an error: {str(text)[:200]}")
            result = message.get("result")
            return result if isinstance(result, dict) else {}

    def initialize(self, timeout: float) -> dict[str, Any]:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-audit", "version": __version__},
            },
            timeout,
        )
        self.notify("notifications/initialized")
        return result

    def list_tools(self, timeout: float) -> list[str]:
        tools = self.request("tools/list", {}, timeout).get("tools")
        if not isinstance(tools, list):
            return []
        return [str(t.get("name", "")) for t in tools if isinstance(t, dict)]

    def call_tool(self, name: str, arguments: dict[str, str], timeout: float) -> ToolResult:
        result = self.request("tools/call", {"name": name, "arguments": arguments}, timeout)
        content = result.get("content")
        items = content if isinstance(content, list) else []
        text = "".join(str(item.get("text", "")) for item in items if isinstance(item, dict))
        return ToolResult(text=text, is_error=result.get("isError") is True)
