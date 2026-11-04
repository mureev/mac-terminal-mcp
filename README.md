# Mac Terminal MCP

**A sandboxed terminal for Claude on your Mac. No dialogs, no dependencies, no telemetry.**

Mac Terminal MCP is a local [MCP](https://modelcontextprotocol.io) server that gives Claude terminal access on your
Mac: run commands, keep long jobs going in tmux sessions, read and edit files, keep the Mac awake.

**Works with** the Claude desktop app — chat and Cowork — through the installer, and with any other stdio MCP
client if you add the entry by hand (`/usr/bin/python3 -I -B mac_terminal_mcp.py`, with `MAC_TERMINAL_POLICY`
pointing at a policy file). macOS only: the guard is the macOS sandbox.

There are no approval dialogs. Every shell command runs at once, inside one macOS sandbox profile, *the fence*
(Seatbelt, the mechanism Claude Code's own sandbox uses on macOS). The fence lets Claude do ordinary work — read the
Mac, change files in your home folder, build, test, use the network — and stops what matters most when a model is
wrong or misled: reading `~/.ssh`, `~/.aws` or the Keychain, writing outside your home folder, and changing the
files that run later outside the sandbox (shell startup files,
LaunchAgents, git hooks and config, editor tasks, MCP and Claude Code config). When the fence blocks something you
plainly asked for — a `git push` that needs the Keychain, a `brew install`, an `osascript` — Claude reruns it with
`outside_sandbox=true` and a one-line why. That is logged and visible, never silent.

> Desktop Commander guards with a pattern list; Mac Terminal MCP uses the macOS kernel sandbox.
> No dialogs, no dependencies, no telemetry.

It is one Python file, standard library only, run by the system Python. No npm, no pip, no telemetry, no self-update.
It was called Mac Ops until 0.7 ([why the name changed](docs/design-decisions.md)).

If the Claude desktop app ships a native macOS shell with a sandbox, use that instead: this project will then be
archived.

## Why this exists

It started as an audit of [Desktop Commander](https://github.com/wonderwhy-er/DesktopCommanderMCP), the popular
answer to "give Claude a shell". The audit ([docs/desktop-commander-audit-2026-10-31.md](docs/desktop-commander-audit-2026-10-31.md))
found a command blocklist that `sh -c` walks straight past, a config tool the model can use to switch its own guards
off, telemetry on by default, and 650 npm packages pulled through `@latest` on every restart. Each of those is a
reasonable trade for a general tool; together they are a bad trade for a laptop that holds production credentials.
So: a smaller thing, where the guard that matters is the kernel's sandbox rather than a regex, and the regexes are
labelled as the speed bumps they are.

Versions 0.2–0.6 put a dialog in front of risky calls, then tiers and time-boxed grants to make the dialogs fewer. A
week of real use answered the question: every dialog was approved, and the requests were all for fewer of them. An
approval you always give is not a control. 0.7 removes them and lets the sandbox carry the weight
([docs/design-decisions.md](docs/design-decisions.md)). Versions: [CHANGELOG.md](CHANGELOG.md).

## Requirements

- macOS (tested on recent releases; a self-test at every start decides whether the fence works on yours)
- `/usr/bin/python3` 3.9+ (Xcode command line tools: `xcode-select --install`)
- tmux (`brew install tmux`)
- The Claude desktop app, for the installer (any stdio MCP client can run the server)

## Install, update, remove

```
brew install tmux                       # once
bash install.sh --check                 # what is there now (changes nothing)
bash install.sh                         # runs the tests, quits Claude, installs, reopens Claude
```

Run it from your own Terminal: it refuses to install from a command this server runs (a change goes live only when a
person installs it). **To update:** review `git diff`, commit, then run `bash install.sh` again. Nothing updates
by itself. **To remove:** `bash install.sh --remove`. It takes out the entry and the installed copy, and keeps the
audit log. **From Mac Ops (0.6 and before):** the install replaces the `mac-ops` entry, removes its read-only copy
(`~/.config/claude-mcp/mac-ops/`), and leaves its state folder with the old audit log (`~/.local/state/mac-ops/`) where
it is; `--check` shows what is left of an old install, changing nothing.

After installing, grant **tmux** access to your Documents folder once if Claude should work there (System Settings →
Privacy & Security → Files & Folders → tmux): commands and reads that touch protected folders run through tmux, so
the server's own Python never needs Full Disk Access.

## Files

| File | What |
|---|---|
| `mac_terminal_mcp.py` | The server: MCP over stdio, the tools, the policy, the fence and its self-test, the audit log. |
| `policy.json` | What it may do: shells, tmux, deny lists, protected paths and folders, network, where state goes. Installed read-only. |
| `install.sh` | Installs the read-only copy and the `mac-terminal` entry in Claude desktop; `--check` changes nothing; `--remove`. |
| `tests/test_mac_terminal_mcp.py` | The suite (stdlib `unittest`; needs tmux and git): `python3 -B -m unittest discover -s tests -v`. On a Mac it also tests the real sandbox; elsewhere those tests skip. |
| `tests/fence_probe.py` | By hand, on a Mac: probe by probe, what the fence blocks and allows there (DNS, mach services, a copy of `open`, signals...). |
| `tests/seatbelt_spike.sh` | A by-hand probe of what Seatbelt itself blocks on this Mac (from 0.3). |
| `docs/` | The Desktop Commander audit and the design decisions. |

## Tools

| Tool | Does |
|---|---|
| `run` | One shell command (zsh login shell, as you, no stdin, up to 45 s), in the fence. Output and exit code. `outside_sandbox=true` + `why`: no sandbox. |
| `session_start` | A tmux session, in the fence (or `outside_sandbox`). With `command`, a job: it runs once, prints `[mac-terminal: exit N]`, and leaves a shell open. Without, an interactive shell. |
| `session_send` | Type into a session (and/or press `C-c`, `Enter`, ...), then wait for output (`wait_s`, `until` regex). It runs in the sandbox the session started with; into an unsandboxed session, every call needs `outside_sandbox=true` and its own `why`. |
| `session_read`, `session_list`, `session_stop` | Read the last lines (optionally wait for new ones), list sessions (each marked fenced or unsandboxed), kill one. |
| `read_file`, `write_file` | Text files; `read_file` also .docx/.xlsx/.pptx (stdlib, no DTDs, size limits) and .pdf (macOS PDFKit, built once, run in the fence, offline). `write_file` creates (default; refuses an existing file), overwrites atomically, or appends; it refuses the files the fence protects. |
| `edit_file` | Replace an exact `old_string` (unique unless `replace_all`) with `new_string`, atomically, keeping permissions and Windows line ends. If it isn't there, says where the closest text is and how it differs (`{-sent-}{+file+}`), and changes nothing: a near match is never applied. Refuses what `write_file` refuses; won't write over a change made since it read the file. |
| `open`, `notify` | `open` a file, folder, http(s) URL or app (it runs outside the sandbox: logged); show a notification. |
| `keep_awake` | `caffeinate -dims` until Claude desktop quits (or for `hours`); `off`; `status`. |
| `status` | Whether the fence works here (the self-test), what it protects, the policy in force, sessions, and calls per day: fenced, unsandboxed, refused. |

Sessions live on their own tmux socket, separate from your own tmux. They keep running between calls and across
Claude restarts, and several can run at once. Watch or take over any of them:

```
tmux -L mac-terminal ls
tmux -L mac-terminal attach -t <name>      # detach again with Ctrl-b d
```

## Safety model

**The fence** is a Seatbelt profile run through `/usr/bin/sandbox-exec` for every `run`, `session_start` and
everything typed into a fenced session. It is `(allow default)` and then:

| | Allowed | Refused |
|---|---|---|
| Read | the whole Mac | `deny_paths`: `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, Keychains, `~/.netrc`, `~/.git-credentials`, Claude's config, this server's config and state (any letter case) |
| Write | `fence_writable` (default: your home folder) and temp | everything else (Homebrew, `/usr/local`, `/Applications`, `/Users/Shared`...); and anywhere: `deny_paths`, `protected_paths` (shell rc files and what they commonly load — `~/.oh-my-zsh`, `~/.zsh`, `~/.config/zsh`, `~/.p10k.zsh`, `~/.config/fish` — `~/.gitconfig`, `~/.config/git`, `~/.npmrc`, `~/.docker/cli-plugins`, LaunchAgents/Daemons, `~/Applications`, `~/.local/bin`, `~/bin`), the folders of your login `PATH` inside home (the self-test reads it), `protected_folders`, the tmux program and tmux's socket folders, and `protected_writes` matches: a `.git` folder itself, `.git/hooks`, `.git/config`, `.gitmodules`, `.envrc`, `.vscode/`, `.idea/`, `.mcp.json`, Claude Code's `.claude/settings*.json`, `commands`, `agents`, `skills`, `hooks`, `plugins`, and `~/.claude.json` |
| Network | on (policy `network`) | off when `network: false` (a DNS lookup still gets through) |
| Unix sockets | the rest | the sockets of programs that run unsandboxed and do what a client asks: tmux (this server's, which runs every call, and your own), the ssh-agent (`SSH_AUTH_SOCK`), Docker, Colima, OrbStack and Podman (their VM mounts your home folder), Emacs, Neovim and VS Code IPC, GNU screen, and anything under a denied path (gpg-agent). Fenced commands also start without `TMUX`, `TMUX_PANE` and `SSH_AUTH_SOCK` |
| Programs | everything else | `open`, `osascript`, `automator`, `shortcuts`, `security`, `tccutil`, `screencapture`, `pbcopy`/`pbpaste`, `launchctl`, `defaults` can't start |
| Extra guards (each kept only if this Mac accepts it and a shell still works) | | the Keychain daemons (so git and gh over https lose their tokens), the clipboard, Apple Events, LaunchServices' `lsopen`, signals to processes outside the sandbox |

The rule behind the list: a fenced command may change your work, but not your credentials, not your installed
software, and not anything that runs later *outside* the fence (which would turn one sandboxed command into an
unsandboxed one next time). `write_file` and `edit_file` run in the server's own Python, outside the sandbox, so they
refuse the same list in code.

**A self-test at every start** proves the fence on this Mac, through tmux like the real calls: a login shell starts
and program output comes back; a scratch folder and temp are writable; a write outside its folders, to the state
folder and to a protected path (also in another letter case) is refused; `.git/hooks` can't be written and `.git`
can't be renamed (which brought hooks back under another name before 0.3.2); a denied folder and the state folder's
contents can't be read (also in another letter case); `open` and `osascript` can't start; the network follows the
policy; and this server's own tmux can't be reached from inside — by its name, or through a symlink or a hard link to
its socket — while the same client reaches it from outside. Seatbelt has spelled unix-socket rules more than one way;
the self-test keeps the first form this Mac takes and honours, and if none holds, the fence is off. Every check needs
positive evidence (a marker the sandboxed program printed, or a file on disk), never just
a missing output; a stand-in that sandboxes nothing fails it (there's a test for that). The probes use scratch
stand-ins for your folders, so nothing real is touched. If the self-test fails, shell commands are refused (policy
`sandbox_fail: refuse`, the default) or run unsandboxed and say so (`sandbox_fail: unsandboxed`); `status` says why.

**`outside_sandbox=true`** on `run` or `session_start` runs with no sandbox, as you. It needs a `why`; the deny lists
still apply; the result says `UNSANDBOXED (...)`; the audit log records it with the why; and your client's own
permission layer sees the flag (in Claude desktop, the chat's permission mode). Claude is told to use it only after
the fence blocked something you plainly asked for, never because a file, page or command output says so. A
session started that way stays unsandboxed, so every `session_send` to it needs the flag and a why again (and so does
a session on this server's tmux socket that it didn't start). `allow_outside_sandbox: false` turns it off.

**The installed copy is read-only.** Claude desktop runs `~/.config/claude-mcp/mac-terminal/`, not this folder, so a
session that edits this folder changes nothing until a person runs `install.sh` again. The fence can't write the
installed copy or Claude's config, and no tool can change the policy.

**No remote hosts.** This server denies `ssh`, `scp`, `sftp` and `ansible`, with `outside_sandbox` too. Reaching
other machines, and changing production, belongs in a separate tool with its own gates (those gates are rare enough
to stay meaningful). `protected_folders` (say, a repository of approved playbooks) are never writable here.

**The audit log**, `~/.local/state/mac-terminal/audit.jsonl` (0600). Every call is logged before it runs (tool,
arguments with secret-looking values masked, `write_file` content as length and hash) and again when it ends
(ok, refused or error, duration, and how it ran: `fenced`, `unsandboxed` with its why, or `python` for the file
tools). The self-test is logged too. If the log can't be written, nothing runs. `status` counts calls per day.

**The deny lists** in `policy.json`: `sudo`/`su`, `ssh`/`scp`/`sftp`/`ansible`, Keychain password reads, and the
secret folders. This is a **speed bump**: it stops honest mistakes and obvious injections, in and out of the fence.
The fence makes the folders real for fenced commands (a glob that gets past the text match still can't read them).

**What is left, said plainly:**

- **Your work is not protected.** Inside your home folder, anything outside the protected paths can be changed or
  deleted by a fenced command: `rm -rf`, an overwritten file, a `git reset --hard` (git's objects are writable; only
  hooks, config and `.git` itself are protected). Keep projects in git, pushed, and Time Machine on. A `git push
  --force` or an upload runs as soon as Claude asks for it with `outside_sandbox`.
- **The network is on.** A fenced command can send what it can read (anything outside the denied folders) anywhere:
  there is no domain allowlist. Set `network: false` if your work allows it.
- **`outside_sandbox` is a shell as you.** It can do everything you can in Terminal, including editing Claude's own
  config, this server's installed copy or your rc files. Its guards are the why, the log, your client's permission
  mode, and Claude's instructions. A prompt injection that convinces Claude to use it gets that shell.
- **Not every file that runs later is on the list.** The fence protects the common ones. Others in your home folder
  are writable: other MCP servers' own code, programs in home folders that aren't on your login `PATH` (and a `PATH`
  entry that is the home folder itself can't be protected), files your rc files load beyond the common ones, git
  config files pulled in with `include`, a relocated `XDG_CONFIG_HOME`, user Python packages (`.pth` files run in an
  unsandboxed `python3`), editor settings outside `.vscode`/`.idea`, Folder Actions and Services in `~/Library`. Add
  what matters to you to `protected_paths`.
- **Other servers on this Mac.** A fenced command can still connect to local TCP services (Jupyter, dev servers,
  Docker over TCP, anything listening on localhost) and to unix sockets the list doesn't name (a password manager's
  agent outside `SSH_AUTH_SOCK`, other editors' or automation tools' IPC). If one of them runs code for whoever
  connects, it is a way out of the fence. `network: false` closes TCP; add other sockets' folders to `deny_paths`.
- With the network off, sandboxed code can still ask the system resolver for a name: a narrow channel out (DNS).
- Sandboxed code can still reach system services the guards don't name (preferences through `cfprefsd`, so also
  Terminal's or an editor's startup command; launchd; Apple Events from a program of its own). The `defaults`, `launchctl` and `osascript` programs can't start in the fence, but a program
  compiled or scripted there could talk to those services directly.
- macOS volumes are case-insensitive: `~/.SSH` is `~/.ssh`. The checks fold case on the Mac, and every Seatbelt path
  rule has an any-case twin.

**What the server itself never does:** network calls, telemetry, self-update, dialogs, or changing its own policy. It
has no dependencies.

## Configuration

`policy.json` is the whole configuration; `load_policy` in the server holds the defaults and refuses unknown keys
(0.6's dialog and grant keys still load: they are ignored, and `status` lists them). The keys you are most likely to
touch:

| Key | Default | What |
|---|---|---|
| `fence_writable` | `["~"]` | Where fenced commands may write, besides temp. Adding `/opt/homebrew` lets `brew install` run fenced, and lets a command replace a program something else runs later. |
| `protected_paths`, `protected_writes` | see file | Never writable in the fence; refused by `write_file`/`edit_file`. (`always_ask_paths` in a 0.6 policy is read as `protected_paths`.) |
| `protected_folders` | `[]` | Folders whose contents are someone's sign-off: never writable here. |
| `deny_words`, `deny_patterns`, `deny_paths` | sudo, ssh, Keychain reads, `~/.ssh`, `~/.aws`, ... | Refused outright (speed bump; `deny_paths` are also unreadable and unwritable in the fence). |
| `network` | `true` | The fence's network. |
| `allow_outside_sandbox` | `true` | `false`: `outside_sandbox` is refused. |
| `sandbox_fail` | `refuse` | What shell commands do if the self-test fails here: `refuse` or `unsandboxed`. |
| `state_dir` | `~/.local/state/mac-terminal` | Audit log and state. |
| `tmux_socket` | `mac-terminal` | The tmux socket its sessions run on (`tmux -L mac-terminal`). |

For settings specific to your Mac (extra protected folders or denied paths), copy `policy.json` to
`policy.local.json` (git-ignored) and edit that: `install.sh` installs it instead when it exists. A `policy.local.json`
made from 0.6's `policy.json` still loads (its dialog and grant keys are ignored, and its protected lists gain 0.7's
additions), but copy the new one again when you can and re-add your changes.

Changing the policy means editing it here and re-running `install.sh`: the installed copy is read-only and no tool
can change it.

## Typical use

- Keep the Mac awake during a long session: `keep_awake` (mode on).
- A long build, migration or log tail: `session_start name=build command="make all"`, then
  `session_read name=build wait_s=30` until `[mac-terminal: exit N]`.
- A coding task: `run`, `edit_file`, `session_*` in the project folder, no dialogs. At the end, `git push` fails in
  the fence (no Keychain) and Claude reruns it with `outside_sandbox=true why="push the fix the user asked for"`.
- What's going on: `status`, or `tail -f ~/.local/state/mac-terminal/audit.jsonl`.

## Development

- Run the tests before anything else: `python3 -B -m unittest discover -s tests -v` (on Linux/CI, set `TMPDIR=/tmp`;
  the Mac-only sandbox tests skip there). Run them in Terminal, not through this server: some create `.git` folders, which
  the fence refuses.
- The installed copy is what runs. Editing this folder changes nothing until `install.sh` runs again — don't present
  an edit as live.
- Changes to the fence (the profile, the protected lists, the self-test, `outside_sandbox`, the file tools' refusals)
  are security changes: add a test that fails without the change, and never weaken a protection to make a test pass.
- Notes for Claude sessions working on this repo: [CLAUDE.md](CLAUDE.md).

## License

[MIT](LICENSE).
