# Design decisions

The reasoning behind Mac Ops, oldest first. The changelog says *what* changed; this says *why*.

**Build rather than install (2026-10-31).** Desktop Commander does the job functionally, but its guardrails don't
hold, it reports home by default, and it brings 650 npm packages onto a laptop that holds production credentials
(`desktop-commander-audit-2026-10-31.md`). Mac Ops is one stdlib-only Python file, run by the system Python, so
nothing changes underneath it between deliberate updates.

**A dialog on the Mac, not the chat's permission mode (v0.2).** A chat in auto mode approves tool calls by itself,
and auto mode alone misses a meaningful share of overeager actions (Anthropic's own published numbers put it around
17%). So the risky tools wait for the user's Allow in a native macOS alert, which the model cannot click.

**A read-only installed copy.** The source folder is writable by every Claude session connected to it. If Claude
desktop ran the server from there, any session could change what the next call runs. `install.sh` copies the server
and policy to `~/.config/claude-mcp/mac-ops/` as read-only files; a change goes live only when a person re-runs the
installer (which is itself tier 2).

**Privacy access through tmux, not the server's Python.** `/usr/bin/python3` also runs other MCP servers; giving it
Documents access would give them all that access. Whatever reads a protected folder runs as a short job in the tmux
server instead, which gets the one macOS privacy grant. `read_file`/`write_file` fall back to tmux where macOS
privacy stops the server's Python.

**Tiers (v0.3).** One dialog per call meant dozens per session; the target is 5–10 at most. The macOS sandbox
(Seatbelt, as Claude Code uses) is what holds, so it is proven by a self-test at every start, with positive evidence
for every check; without it, every call asks as before. The allowlist only decides what may skip the dialog — a
command it misjudges still can't write.

**Borrow, don't adopt (v0.3.2).** A second look at Desktop Commander and Anthropic's sandbox-runtime: keep Mac Ops,
take Desktop Commander's targeted edit and sandbox-runtime's protected-file list, and test our profiles against
sandbox-runtime's (`tests/sandbox_runtime_experiment.py`).

**No remote hosts (v0.4.0).** Code that can change production shouldn't live in a Mac shell that changes often.
Remote work moved to a separate server with its own gates; this one denies `ssh`, `scp` and `ansible`.
`protected_folders` (0.6.0) keeps the other half of that idea generic: folders whose contents are someone's
sign-off are never a grant folder.

**Fewer dialogs by fixing leaks, not loosening tiers (v0.5.x).** Dialogs should be readable (one step per line,
Claude's stated reason labelled as Claude's), and most excess dialogs turned out to be leaks — a forgotten grant
token, a harmless `VAR=` prefix, a scary word inside a grep pattern — rather than tier 1 doing its job. Each was
fixed narrowly, with a test. A wider "allow everything for a while" button was tried in 0.5.0 and removed in 0.5.1.

**Changes to the approval code are reviewed by a person.** An auto-mode safety check once stopped Claude from
applying a change to this server's own approval code. That is the right outcome: such changes are handed over as a
patch, tested, and applied by a person.
