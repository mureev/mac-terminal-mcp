# Mac Ops

**Claude's hands on your Mac, with a leash you can actually see.**

Mac Ops is a local [MCP](https://modelcontextprotocol.io) server for the Claude desktop app (Cowork and chat). It lets
Claude run shell commands, keep long jobs going in tmux sessions, read and edit files, and keep the Mac awake — while
you click *Allow* a handful of times per working session instead of once per command.

The trick is tiers. Commands that provably only read run in a read-only, offline macOS sandbox (Seatbelt, the same
mechanism Claude Code uses) and never ask. Everything else either asks once, or runs under a *grant*: one dialog
opens a time-boxed, folder-scoped, optionally-networked sandbox for a task, and calls carrying its token go through
quietly. A short list of things that are dangerous no matter what — `git push`, cloud CLIs, uploads, `osascript`,
writes to `.git/hooks` or your shell rc files — always asks, grant or not. Every call lands in an audit log before it
runs.

It is one Python file, standard library only, run by the system Python. No npm, no pip, no telemetry, no self-update.

## Why this exists

It started as an audit of [Desktop Commander](https://github.com/wonderwhy-er/DesktopCommanderMCP), the popular
answer to "give Claude a shell". The audit ([docs/desktop-commander-audit-2026-10-31.md](docs/desktop-commander-audit-2026-10-31.md))
found a command blocklist that `sh -c` walks straight past, a config tool the model can use to switch its own guards
off, telemetry on by default, and 650 npm packages pulled through `@latest` on every restart. Each of those is a
reasonable trade for a general tool; together they are a bad trade for a laptop that holds production credentials.
So: a smaller thing, where the guard that matters is the kernel's sandbox rather than a regex, and the regexes are
labelled as the speed bumps they are.

Design history: [docs/design-decisions.md](docs/design-decisions.md). Versions: [CHANGELOG.md](CHANGELOG.md).

## Requirements

- macOS (tested on recent releases; the sandbox self-test decides at every start whether tiers work on yours)
- `/usr/bin/python3` 3.9+ (Xcode command line tools: `xcode-select --install`)
- tmux (`brew install tmux`)
- The Claude desktop app

## Install, update, remove

```
brew install tmux                       # once
bash install.sh --check                 # what is there now (changes nothing)
bash install.sh                         # runs the tests, quits Claude, installs, reopens Claude
```

**To update:** review `git diff`, commit, then run `bash install.sh` again. Nothing updates by itself.

**To remove:** `bash install.sh --remove`. It takes out the entry and the installed copy, and keeps the audit log.

After installing, grant **tmux** access to your Documents folder once if Claude should work there (System Settings →
Privacy & Security → Files & Folders → tmux): reads and commands that touch protected folders run through tmux, so
the server's own Python never needs Full Disk Access.

## Files

| File | What |
|---|---|
| `mac_ops_server.py` | The server: MCP over stdio, the tools, the policy, the sandbox profiles, the audit log. |
| `policy.json` | What it may do: shells, tmux, deny lists, protected folders, tier-2 rules, where state goes. Installed read-only. |
| `install.sh` | Installs the read-only copy and the `mac-ops` entry in Claude desktop; `--check` changes nothing; `--remove`. |
| `tests/test_mac_ops.py` | The suite (stdlib `unittest`; needs tmux and git): `python3 -B -m unittest discover -s tests -v`. On a Mac it also tests the real sandbox; elsewhere those tests skip. |
| `tests/seatbelt_spike.sh` | A by-hand probe of what the sandbox blocks on this Mac (writes, network, Apple Events, clipboard, signals). |
| `tests/sandbox_runtime_experiment.py` | By hand: our self-test and probes under our profiles and under Anthropic sandbox-runtime 0.0.81's (`tests/srt-0.0.81-profiles.json`, generated once from the npm package; srt never runs on the Mac). |
| `docs/` | The Desktop Commander audit and the design decisions. |

## Tools

| Tool | Does |
|---|---|
| `run` | One shell command (zsh login shell, as you, no stdin, up to 45 s). Output and exit code. Reads run sandboxed without asking; `grant` for the rest. |
| `session_start` | A tmux session. With `command`, a job: it runs once, prints `[mac-ops: exit N]`, and leaves a shell open. Without, an interactive shell. |
| `session_send` | Type into a session (and/or press `C-c`, `Enter`, ...), then wait for output (`wait_s`, `until` regex). |
| `session_read`, `session_list`, `session_stop` | Read the last lines (optionally wait for new ones), list sessions, kill one. |
| `read_file`, `write_file` | Text files; `read_file` also .docx/.xlsx/.pptx (stdlib, no DTDs, size limits) and .pdf (macOS PDFKit, built once, run in the read-only sandbox). `write_file` creates (default; refuses an existing file), overwrites atomically, or appends. |
| `edit_file` | Replace an exact `old_string` (unique unless `replace_all`) with `new_string`, atomically, keeping permissions and Windows line ends. If it isn't there, says where the closest text is and how it differs (`{-sent-}{+file+}`), and changes nothing: a near match is never applied. Asks like `write_file`; won't write over a change made while its dialog was up. |
| `open`, `notify` | `open` a file, folder, http(s) URL or app (files and web addresses ask: `open` runs outside the sandbox); show a notification. |
| `request_grant` | One dialog: purpose, folders, minutes, network. Returns a token for this chat; calls carrying it run without asking, sandboxed to those folders. |
| (dialogs) | A call without a grant shows Don’t Allow / Allow Once (for a series of calls, `request_grant` first). `why` (on run, session_*, write_file, edit_file) heads the dialog. `python3 mac_ops_server.py --preview-dialogs` shows them all. |
| `revoke_grant`, `approval_status` | End a grant; show tiers vs every-call, the sandbox self-test, active grants (no tokens), dialogs per day. |
| `keep_awake` | `caffeinate -dims` until Claude desktop quits (or for `hours`); `off`; `status`. |

Sessions live on their own tmux socket, separate from your own tmux. They keep running between calls and across
Claude restarts, and several can run at once. Watch or take over any of them:

```
tmux -L claude ls
tmux -L claude attach -t <name>      # detach again with Ctrl-b d
```

## Safety model

**What it is not:** a sandbox for approved calls. "Allow Once" and tier 2 run a shell as you.
Anything you can do in Terminal, such a call can do, including reading the Keychain items your installers created
(`security` is on "Always Allow" for them).

**What keeps it safe, in order of strength:**

1. **Approvals in three tiers** (policy `approvals: tiers`, the gated tools in `confirm_tools`):

   | Tier | What | Asks? | Runs |
   |---|---|---|---|
   | 0 | `run`/`session_start` commands an allowlist proves read-only (ls, cat, grep, rg, find, git status/log/diff/show, ps, du...; pipes of them) | no | read-only sandbox, no network |
   | 1 | everything else on the Mac | once per task: `request_grant`, or "Allow N min" in a call's dialog | the grant's sandbox: writes only in its folders, temp and build caches; network only if granted |
   | 2 | `always_ask` and `always_ask_programs` in policy.json: git push and history rewrites, gh changes, cloud and cluster CLIs, docker, uploads, publishing, launchctl/crontab, defaults write/security/system settings, osascript, killall/pkill (when they are what runs), Mac Ops' own install.sh, rsync to a host; writes to rc files, LaunchAgents, `.git` itself, `.git/hooks`, `.git/config`, `.gitmodules`, `.envrc`, `.vscode/`, `.idea/`, `.mcp.json`, `.claude/commands`/`agents` (any letter case); `open` of a file or web address | every time, no grant covers it | unsandboxed, exactly what you allowed |

   Dialogs are macOS alerts: a bold headline saying what Claude wants ("Claude wants to run a command"), the exact
   command or file and where, and what the buttons do. Without a grant they offer **Don't Allow / Allow Once / Allow
   for 60 Minutes** (the last when the call's folder can be a grant folder); tier 2 carries the caution badge and
   offers only Allow Once. Don't Allow is the default button; no answer within 40 s or no dialog means refused.
   `python3 -I -B mac_ops_server.py --preview-dialogs` shows each kind with sample content. **A Don't Allow also
   revokes the grant the call carried**, a tripwire for a chat doing something you didn't expect. Grant tokens live only in
   the server's memory (quitting Claude revokes them all), only the chat that got one knows it (the server can't
   tell chats apart, so the token is the chat's identity), Claude can't create or extend one, and the audit log
   keeps only their first characters. Grant folders must be project folders: not your home or its top-level
   folders, not ~/Library, not overlapping a denied path. Defaults: 60 minutes, at most 240, 1000 calls, 5 folders.
   Your chat's own permission mode (auto or ask) still sees every call on top of all this.

2. **The sandbox** is macOS Seatbelt through `/usr/bin/sandbox-exec`, the mechanism Claude Code's own sandbox uses on
   macOS. Profiles: `(allow default)`, then deny network (unless granted), deny every write outside the allowed
   folders, deny reads and writes of `deny_paths` and the state folder (only its contents: programs fstat their output file there), deny writes to `always_ask_paths` and
   `protected_writes`, and refuse to start the programs that act outside the sandbox on its behalf: `open` (hands
   files and URLs to other apps), `osascript`, `automator`, `shortcuts`, `security`, `tccutil`, `screencapture`,
   `pbcopy`/`pbpaste`, `launchctl`, `defaults`. (On macOS 27 a LaunchServices deny did not stop `open` launching
   apps, and Apple Events were not reliably refused, so those programs can't start at all.) Extra guards, each kept
   only if this Mac accepts it, a shell still works with it and, where it can be shown, it works: Apple Events and
   LaunchServices' own `lsopen` (best effort; a copy of `open` in temp is not the guarded path), the clipboard, the Keychain daemons (under every grant too, so git and gh over https can't read their
   tokens in the sandbox: a fetch from a private repo asks), and signals to processes outside the sandbox (proven by
   trying to kill one). **A self-test at every start** proves, through tmux like the real calls, that writes outside
   temp, reads of denied folders (also spelled in another letter case) and the network are blocked, that a grant
   writes only its folder, not `.git/hooks`, and can't rename `.git` (which brought hooks back under another name
   before v0.3.2), that `open` and `osascript` can't start, and that a login shell works and program output comes back.
   Each check needs positive evidence (a marker the sandboxed program printed, or a file on disk), never just a
   missing output. Every run uses its own scratch paths (two servers start together when two chats do), and a failed
   self-test is retried once. If it still fails, approvals fall back to every call asking (v0.2) and `approval_status` says
   why. The allowlist decides what may skip the dialog; the sandbox is what stops a write or a connection, so a
   command the allowlist misjudges still can't write.

3. **The installed copy is read-only.** Claude desktop runs `~/.config/claude-mcp/mac-ops/`, not this folder, so a
   session that edits this folder changes nothing until `install.sh` runs again (tier 2: it always asks). No tool
   can change the policy.

4. **No remote hosts.** This server denies `ssh`, `scp`, `sftp` and `ansible`. Reaching other machines belongs in a
   separate tool with its own gates. Folders listed in `protected_folders` (say, a repository of approved playbooks,
   or one another, stricter tool owns) are never a grant folder, so every write there asks.

5. **The audit log**, `~/.local/state/mac-ops/audit.jsonl` (0600). Every call is logged before it runs (tool,
   arguments with secret-looking values masked, `write_file` content as length and hash, grant tokens cut) and again
   when it ends (ok, refused or error, duration, tier, and how it ran: read, grant or unsandboxed). Dialogs, grants,
   revocations and the self-test are logged too. If the log can't be written, nothing runs. `approval_status`
   counts dialogs per day, to check the 5–10 target against numbers.

6. **The deny lists** in `policy.json`: `sudo`/`su`, `ssh`/`scp`/`sftp`/`ansible`, Keychain
   reads, and secret folders (`~/.ssh`, `~/.aws`, Keychains, Claude's config, this server's own config and
   state). This is a **speed bump**: it stops honest mistakes and obvious injections. The sandbox makes the folders
   real for sandboxed calls (a glob that gets past the text match still can't read them).

**What is left, said plainly:**

- Inside a grant, anything in its folders can be changed or deleted, by a command that isn't what it looks like
  too. Grant project folders that are in git. Reads (tier 0 and grants) reach the whole Mac except the denied
  folders, as `read_file` always did.
- A network grant can send data anywhere: there is no domain allowlist, and a plain `curl https://host/<data>` is
  not tier 2. Grant network only when the task needs it.
- Since v0.5.2 an Allow Once also covers the identical call for 5 minutes, from any chat: what you allowed, again.
  And a grant hint tells another chat that a grant exists in that folder (its first 6 characters and end time).
- Since v0.5.2 tier 2's program words count only where they run. A program reached some other way (an
  interpreter's `os.system`, a script file that calls `security`) was never tier 2 and still isn't; the grant's
  sandbox is what holds there (`security`, `osascript`, `defaults` and `launchctl` can't start in it).
- Reads may use only harmless variables (`$HOME`, `$PWD`, `$USER`...): `echo $SOME_TOKEN` asks. Files are another
  matter: tier 0, like `read_file` always, can read `~/.zprofile` and any other file outside the denied folders.
- macOS volumes are case-insensitive: `~/.SSH` is `~/.ssh`. The deny and always-ask checks fold case on the Mac,
  and every Seatbelt path rule has an any-case twin (v0.3.2).
- With the network off, sandboxed code can still ask the system resolver for a name: a narrow channel out (DNS)
  that the profile doesn't close.
- Sandboxed code can still reach system services the guards don't name (preferences, launchd, Apple Events from a
  program of its own). The `defaults`, `launchctl` and `osascript` programs can't start in the sandbox, and their
  changes are tier 2, but a program compiled or scripted under a grant could talk to those services directly.
- A prompt injection in the chat that holds a token can use it, within its folders, minutes and network. That is
  what the bounds are for, and why a Deny revokes.
- MCP elicitation (approving in the Claude app, e.g. from the phone) isn't offered by Claude desktop yet;
  `approval_status` shows when the client starts offering it.

**What the server itself never does:** network calls, telemetry, self-update, or changing its own policy. It has no
dependencies.

## Configuration

`policy.json` is the whole configuration; `load_policy` in the server holds the defaults and refuses unknown keys.
The keys you are most likely to touch:

| Key | Default | What |
|---|---|---|
| `protected_folders` | `[]` | Folders no grant may cover; writes there always ask. |
| `deny_words`, `deny_patterns`, `deny_paths` | sudo, ssh, Keychain reads, `~/.ssh`, `~/.aws`, ... | Refused outright (speed bump; `deny_paths` are also enforced by the sandbox). |
| `always_ask`, `always_ask_programs`, `always_ask_paths`, `protected_writes` | see file | Tier 2: asks every time. |
| `grant_minutes`, `grant_max_minutes`, `grant_max_calls`, `grant_max_folders` | 60, 240, 1000, 5 | Grant bounds. |
| `allow_repeat_minutes` | 5 | After an Allow Once, the identical call runs again without asking for this long (0 = off). |
| `approvals` | `tiers` | `every` makes every gated call ask (the v0.2 behaviour). |
| `state_dir` | `~/.local/state/mac-ops` | Audit log and state. |

For settings specific to your Mac (extra protected folders or denied paths), copy `policy.json` to
`policy.local.json` (git-ignored) and edit that: `install.sh` installs it instead when it exists.

Changing the policy means editing it here and re-running `install.sh`: the installed copy is read-only and
no tool can change it.

## Typical use

- Keep the Mac awake during a long session: `keep_awake` (mode on).
- A long build, migration or log tail: `session_start name=build command="make all"`, then
  `session_read name=build wait_s=30` until `[mac-ops: exit N]`.
- A coding task: `request_grant purpose="fix the export script" folders=["~/Documents/.../repo"] minutes=60` (one
  dialog), then `run`/`write_file`/`session_*` with that `grant`; a `git push` at the end asks once more.
- What's going on with approvals: `approval_status`.

## Development

- Run the tests before anything else: `python3 -B -m unittest discover -s tests -v` (on Linux/CI, set `TMPDIR=/tmp`;
  the Mac-only sandbox tests skip there).
- The installed copy is what runs. Editing this folder changes nothing until `install.sh` runs again — don't present
  an edit as live.
- Changes to the approval code (tiers, the read allowlist, grants, the sandbox profiles) are security changes: add a
  test that fails without the change, and never weaken a protection to make a test pass.
- `python3 -I -B mac_ops_server.py --preview-dialogs` shows every kind of dialog without running anything.
- Notes for Claude sessions working on this repo: [CLAUDE.md](CLAUDE.md).

## License

Not chosen yet. Until a `LICENSE` file is added, all rights are reserved by the author.
