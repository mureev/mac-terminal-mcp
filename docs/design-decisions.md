# Design decisions

The reasoning behind Mac Terminal MCP (Mac Ops until 0.7), oldest first. The changelog says *what* changed; this says *why*.

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
sandbox-runtime's (`tests/sandbox_runtime_experiment.py`, in the history up to 0.6.0).

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

**No dialogs (v0.7, 2026-11-04).** A week of daily use with tiers and grants: every dialog was approved, and the
only requests were for fewer of them, five times; even a second dialog in a session was too many. An approval that is
always given is a ritual, not a control, and worse than none: it habituates, so the one bad request gets the same
click as the two hundred good ones. Structural controls don't habituate. So the sandbox, which was already what held
under a grant, now holds for every shell call, with no question asked: one profile, the fence, that lets commands
change your work but not your credentials, your installed software, or anything that runs later outside it. What it
blocks and you plainly want goes through `outside_sandbox` with a stated why, logged and visible to the client's own
permission layer, instead of through a dialog. Claude Code's sandbox reached the same design (auto-allow: sandboxed
commands run without prompts; the rest falls back to the permission flow). Two choices beyond "the grant profile
without the grant": writes are limited to the home folder and temp, because once writes are free, a writable
Homebrew or `/Applications` lets a fenced command replace a program that something unsandboxed runs later (this
server's own tmux among them); and Claude Code's settings, hooks and plugins joined the protected files for the same
reason. The same rule covers sockets: a server that runs unsandboxed and does what a client asks (this server's
tmux above all, also the ssh-agent and container runtimes) is a way out of the fence if a fenced command can connect
to it, so the fence denies those connections, and the self-test must prove the tmux one before the fence is used.
Gates stay where they are rare and high-stakes: production changes live in a separate tool, whose few
approvals still mean something.

**A name people search for (v0.7, 2026-11-04).** "Mac Ops" read as Mac fleet management (Google's macops is exactly
that), and nobody looking for this types "ops". People look for a terminal, for their Mac, and for MCP, so the name
is all three: Mac Terminal MCP, `mac-terminal-mcp`. Claude and Cowork stay in the description, not the name: the
server speaks plain MCP, and a product name in it would say otherwise. The tmux socket moved from the generic
`claude`, which another tool could also pick, to `mac-terminal`.
