# Changelog

## 0.7.0 — 2026-11-04 — no dialogs

The approval system is gone; the macOS sandbox carries the weight (design-decisions: "No dialogs").

- **No dialogs, tiers or grants.** Removed: the macOS alerts, `request_grant`/`revoke_grant` and grant tokens, the
  read-only classifier (tier 0), the always-ask lists (tier 2), the allow-repeat window, grant hints, approvals
  `every`, `--preview-dialogs`. `approval_status` is now `status`.
- **The fence:** one Seatbelt profile for every `run`, `session_start` and fenced session. Reads everywhere but
  `deny_paths`; writes only under `fence_writable` (new; default the home folder) and temp, never to `deny_paths`, the
  state folder, `protected_paths`, `protected_folders`, the tmux program, or a `protected_writes` match; network per
  `network` (new; default on); the exec guard and the extra guards as before.
- **No way back out through a server that runs unsandboxed.** Fenced commands can't connect to tmux's sockets (this
  server's, which runs every call, and the user's own), the ssh-agent, Docker/Colima/OrbStack/Podman, Emacs, Neovim,
  VS Code IPC, GNU screen, or sockets under denied paths; they can't write tmux's socket folders; they start without
  `TMUX`, `TMUX_PANE`, `SSH_AUTH_SOCK`. The tmux rule is core: the self-test proves it (by name, symlink and hard
  link, against the live server) and keeps the first Seatbelt form this Mac honours. (0.6 had this hole under
  network grants.) The login `PATH`'s folders inside home are protected; so are `~/.oh-my-zsh`, `~/.zsh`,
  `~/.config/zsh`, `~/.p10k.zsh`, `~/.config/fish`, `~/.npmrc`, `~/.docker/cli-plugins`; `~/.config/gh` is denied.
- **`outside_sandbox=true`** on `run` and `session_start`: no sandbox, with a required `why`; the deny lists still
  apply; logged with the why; `allow_outside_sandbox` (new; default true) turns it off. A session started that way
  stays unsandboxed: every `session_send` to it needs the flag and a why too; `session_list` and `status` mark it.
- **write_file and edit_file** refuse what the fence protects, in the server's own Python, and otherwise write without
  asking. `open` no longer asks (logged).
- **Self-test** rebuilt for the fence, with scratch stand-ins for the policy's folders. If it fails: `sandbox_fail`
  (new): `refuse` (default) or `unsandboxed`. A test proves a sandbox that sandboxes nothing fails it.
- **Policy:** `always_ask_paths` is now `protected_paths` (a 0.6 policy's list is read as it), with `~/Applications`,
  `~/.local/bin` and `~/bin` added; `protected_writes` adds Claude Code's `.claude/settings*.json`, `skills`, `hooks`,
  `plugins` and `~/.claude.json`. 0.6's dialog and grant keys are ignored and listed by `status`, and a 0.6 policy's
  protected and denied lists gain 0.7's additions. The server runs `ps` and `pgrep` by absolute path.
- **Audit log:** each call's end records `how`: `fenced`, `unsandboxed` (with its why) or `python`.
- `install.sh` refuses to install from a command Mac Ops runs (`MAC_OPS` set; `--check` still works).
- `tests/fence_probe.py` replaces the 0.3.2 sandbox-runtime experiment (it compared read and grant profiles that no
  longer exist; it and `srt-0.0.81-profiles.json` are in the 0.6.0 history). `tests/policy-0.6.0.json`: the 0.6 policy,
  to test that it still loads.
- License: MIT.

## 0.6.0 — 2026-11-03 — standalone

Mac Ops leaves the private workspace it grew up in and becomes its own project.

- `protected_folders` (a list, default empty) replaces a single, hard-coded protected path: folders no grant may
  cover, writes there always ask.
- Removed deployment-specific defaults: a deny pattern for one repository's `bin/run`/`bin/capture` scripts and a
  sibling tool's state folder in `deny_paths`.
- Tool descriptions and dialogs speak of "the user" instead of a named person.
- `tests/srt-0.0.81-profiles.json` stores the home folder as `__HOME__`; the experiment substitutes the real one.
- New README, CHANGELOG, `docs/design-decisions.md`, `CLAUDE.md`. Fresh git history.

## 0.5.2 — 2026-11-03

After a review of the audit log (38% of 0.5.1's calls asked; the target is 5–10 dialogs a session): most dialogs
were leaks, not tier 1 doing its job.

1. **Grant hint.** A tier-1 call with no token, in a folder a live grant covers, is refused once without a dialog,
   telling Claude to pass its token. The same call again asks as before (it may come from a chat without the grant);
   only the token's first 6 characters are shown.
2. **Reads.** `GIT_OPTIONAL_LOCKS=0` and a few other print-only `VAR=value` prefixes are allowed (not `PAGER` and the
   like); a `$` or backtick inside single quotes is literal (`grep -v '^$'`); `ioreg` reads.
3. **Tier 2 by program.** `security`, `nvram`, `osascript`, `killall` and the rest of `always_ask_programs` ask when
   they are what runs (first word of a step, after `sudo`/`env`/`xargs`/`time`, a shell's script or `-c` text,
   `find -exec`), not when they appear in a grep pattern or a file name. A command that can't be parsed still asks on
   any mention. `install.sh` is tier 2 only for Mac Ops' own.
4. **Repeats.** After an Allow Once, the identical tier-1 call (same tool, text and folder) runs again without a
   dialog for `allow_repeat_minutes` (5; 0 turns it off). Never for tier 2.

## 0.5.1 — 2026-11-03

**More Options… removed.** Its second dialog was a slow, plain AppleScript list, not worth having. A call without a
grant shows Don't Allow / Allow Once again; grants come only from `request_grant`, and the allow-everything grant is
gone. The three `*_minutes` policy keys are ignored if still present.

## 0.5.0 — 2026-11-02

Dialogs you can read. The command shows one step per line (split at `&&`, `||`, `;` and newlines outside quotes;
every character still shown), with Claude's own one-line `why` on top, labelled as Claude's words, the programs it
runs, and a last line saying where the request comes from (server, client, process; the chat when the client names
one). Added a More Options… button (removed again in 0.5.1).

## 0.4.0 — 2026-11-02

No remote hosts. The tools that applied changes to production hosts moved out to a separate, dedicated server: code
that can change production should not live in a Mac shell that changes often. This server denies `ssh` and
`ansible`.

## 0.3.2 — 2026-11-01

After re-checking Desktop Commander and Anthropic's sandbox-runtime against this code: `edit_file` (Desktop
Commander's targeted edit; a near match is shown, never applied); `read_file` reads .docx/.xlsx/.pptx and .pdf;
sandbox-runtime's protected-file list (`.git` itself, `.gitmodules`, `.vscode`, `.idea`, `.mcp.json`,
`.claude/commands|agents`); any-case twins for every Seatbelt path rule; `tests/sandbox_runtime_experiment.py`. Fixed
a self-test race when two servers started together, which turned tiers off.

## 0.3.1 — 2026-11-01

Dialogs as macOS alerts with a headline that says what Claude wants.

## 0.3 — 2026-10-31

Tiered approvals. v0.2's one dialog per call meant dozens per session. Now: reads sandboxed and free; task grants
(one dialog, this chat only, folders + minutes + network) for the rest; tier 2 always asks. The Seatbelt sandbox is
what holds, proven by a self-test at every start; without it every call asks as before. `open` and `osascript`
can't start inside the sandbox; the self-test needs positive evidence. `run` and protected-folder reads go through
tmux (one macOS privacy grant, on tmux).

## 0.2 — 2026-10-31

Risky calls wait for the user's Allow in a dialog on the Mac (once it turned out that a chat in auto mode approves
tool calls by itself).

## 0.1 — 2026-10-31

First version: a local MCP server for Claude's shell, sessions and files on the Mac, built instead of installing
Desktop Commander.
