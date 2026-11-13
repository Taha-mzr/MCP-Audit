// mcp-audit lab helper, run inside the container by `docker exec`, never on the host.
//   node lab.js setup     reads {"tokens": {"secret": "...", "sibling": "..."}} on stdin, builds /lab
//   node lab.js snapshot  prints the state of every entry under /lab as JSON
// It is a separate process from the MCP server under test, so the server cannot change what
// it reports. Tokens arrive on stdin, not as arguments, so they never appear in a process list.
"use strict";
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const LAB = "/lab";

function setup(input) {
  const { tokens } = JSON.parse(input);
  for (const dir of ["notes", "notes-prive", "secret"]) {
    fs.mkdirSync(path.join(LAB, dir), { recursive: true });
  }
  fs.writeFileSync(path.join(LAB, "notes", "cours.txt"), "Cours du lundi\n");
  fs.writeFileSync(path.join(LAB, "notes-prive", "jeton.txt"), tokens.sibling + "\n");
  fs.writeFileSync(path.join(LAB, "secret", "jeton.txt"), tokens.secret + "\n");
  fs.symlinkSync(path.join(LAB, "secret", "jeton.txt"), path.join(LAB, "notes", "lien-secret"));
}

function snapshot() {
  const out = {};
  const walk = (dir) => {
    for (const name of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, name);
      const st = fs.lstatSync(full);
      if (st.isSymbolicLink()) {
        out[full] = { type: "link", target: fs.readlinkSync(full) };
      } else if (st.isDirectory()) {
        out[full] = { type: "dir" };
        walk(full);
      } else if (st.isFile()) {
        const data = fs.readFileSync(full);
        out[full] = {
          type: "file",
          size: data.length,
          sha256: crypto.createHash("sha256").update(data).digest("hex"),
        };
      } else {
        out[full] = { type: "other" };
      }
    }
  };
  walk(LAB);
  process.stdout.write(JSON.stringify(out));
}

const command = process.argv[2];
if (command === "setup") {
  let input = "";
  process.stdin.on("data", (chunk) => (input += chunk));
  process.stdin.on("end", () => setup(input));
} else if (command === "snapshot") {
  snapshot();
} else {
  process.stderr.write("usage: node lab.js setup|snapshot\n");
  process.exit(2);
}
