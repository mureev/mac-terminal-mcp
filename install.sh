#!/bin/bash
# Installs Mac Terminal MCP ("mac-terminal") in the Claude desktop app: a sandboxed terminal for Claude on this Mac.
# It reaches no remote host (ssh, scp, ansible are denied). No dialogs (v0.7): every shell command runs in the fence,
# a macOS sandbox that protects credentials and the files that run later; outside_sandbox (with a why) is the logged
# exception. Upgrading from Mac Ops (0.6 and before, "mac-ops"): the install replaces its entry and its installed copy,
# and leaves its state folder (the old audit log) where it is.
#
#   bash install.sh                install, or update to what this folder holds now (review `git diff` first)
#   bash install.sh --check        change nothing: installed copy vs this folder, the Claude entry, tmux, the audit
#                                  log, keep_awake, the sessions, and any old Mac Ops install
#   bash install.sh --remove       remove the mac-terminal entry and its installed copy (keeps its state folder)
#   bash install.sh --skip-tests   install without running the tests first
#
# Why a copy. This folder is writable by every Claude session connected to it. If Claude desktop ran the server from
# here, any session could change what the next call runs. So this script copies mac_terminal_mcp.py and policy.json
# to ~/.config/claude-mcp/mac-terminal/ (read-only files), and Claude desktop runs that copy with the system Python
# (/usr/bin/python3 -I -B). Updating = review the diff, commit, run this script again. No package manager is involved:
# the server is one file of Python's standard library, so nothing changes under you between updates.
#
# What it does, in order:
#   1. Checks /usr/bin/python3 (3.9 or newer), tmux (brew install tmux) and policy.json.
#   2. Runs the tests (tmux sessions on a test socket, temporary folders; nothing outside them is touched).
#   3. Quits Claude while its config is edited, so the app can't write an older copy back. Reopens it at the end.
#   4. Installs the read-only copy (policy.json gets tmux's full path), checks it answers the MCP handshake, and
#      runs the sandbox self-test (if it fails, shell commands are refused, or run unsandboxed if the policy's
#      sandbox_fail says so; the file tools keep working).
#   5. Backs up claude_desktop_config.json to ~/.config/claude-mcp/backups/, then adds or replaces ONLY the
#      mac-terminal entry (and removes an old mac-ops one). Every other entry is kept; the result is parsed back
#      before it replaces the file.
#   6. Removes an old Mac Ops copy at ~/.config/claude-mcp/mac-ops/ (that folder only).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="mac-terminal"; TITLE="Mac Terminal MCP"; SERVER_PY="mac_terminal_mcp.py"; ENV_PREFIX="MAC_TERMINAL"
OLD_NAME="mac-ops"; OLD_TITLE="Mac Ops"; OLD_SOCKET="claude"     # 0.6 and before
DEST="${MCP_DEST:-$HOME/.config/claude-mcp}"
INST="$DEST/$NAME"
OLD_INST="$DEST/$OLD_NAME"
OLD_STATE="$HOME/.local/state/$OLD_NAME"
CFG="${CLAUDE_CONFIG:-$HOME/Library/Application Support/Claude/claude_desktop_config.json}"
PY=/usr/bin/python3

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mSTOPPED: %s\033[0m\n' "$*" >&2; exit 1; }

MODE=install; TESTS=1
for a in "$@"; do
  case "$a" in
    --check) MODE=check ;;
    --remove) MODE=remove ;;
    --skip-tests) TESTS=0 ;;
    -h|--help) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown argument '$a'. Use --check, --remove, --skip-tests, or nothing to install." ;;
  esac
done
# A change goes live only when a person installs it: not from a command this server runs (it sets MAC_TERMINAL=1;
# Mac Ops set MAC_OPS=1). A speed bump like the deny lists (outside_sandbox is a shell as you), and it says so.
if { [ -n "${MAC_TERMINAL:-}" ] || [ -n "${MAC_OPS:-}" ]; } && [ "$MODE" != check ]; then
  die "install.sh runs from your own Terminal, not through $TITLE or $OLD_TITLE. --check is fine from anywhere."
fi

[ -x "$PY" ] || die "No $PY. Install the Xcode command line tools (xcode-select --install)."
"$PY" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "$PY is older than 3.9. Update the Xcode command line tools (xcode-select --install)."
TMUX_BIN="$(command -v tmux || true)"
for c in /opt/homebrew/bin/tmux /usr/local/bin/tmux; do [ -z "$TMUX_BIN" ] && [ -x "$c" ] && TMUX_BIN="$c"; done
# A policy.local.json next to policy.json (git-ignored) is installed instead of it: this Mac's own folders and paths.
POLICY_SRC="$HERE/policy.json"; [ -f "$HERE/policy.local.json" ] && POLICY_SRC="$HERE/policy.local.json"
pol() {  # pol KEY DEFAULT: a value of the policy being installed (lists joined with ", ")
  "$PY" -I -c 'import json,os,sys; v=json.load(open(sys.argv[1])).get(sys.argv[2], sys.argv[3]); print(", ".join(os.path.expanduser(x) for x in v) if isinstance(v, list) else os.path.expanduser(v))' "$POLICY_SRC" "$1" "$2"
}
PROTECTED="$(pol protected_folders "")"; PROTECTED="${PROTECTED:-none}"
STATE="$(pol state_dir "~/.local/state/$NAME")"
SOCKET="$(pol tmux_socket "$NAME")"

claude_running() { [ -z "${SKIP_APP_CONTROL:-}" ] && pgrep -x Claude >/dev/null 2>&1; }
quit_claude() {
  claude_running || return 0
  say "Claude is open. It has to be closed while its config is edited."
  read -r -p "  Quit Claude now? It reopens at the end. [Y/n] " a
  [[ "$a" =~ ^[Nn]$ ]] && die "Quit Claude (Cmd+Q) and run this again."
  osascript -e 'quit app "Claude"' >/dev/null 2>&1 || true
  echo "  (if Claude asks whether to quit while a task runs, click Quit)"
  for _ in $(seq 1 90); do claude_running || break; sleep 1; done
  claude_running && die "Claude didn't quit. Quit it with Cmd+Q and run this again."
  ok "Claude closed"
  REOPEN=1
  trap 'open -a Claude >/dev/null 2>&1 && printf "  Claude reopened\n"' EXIT
}
backup_cfg() {
  mkdir -p "$DEST/backups"; chmod 700 "$DEST" "$DEST/backups"
  if [ -f "$CFG" ]; then
    BK="$DEST/backups/claude_desktop_config.$(date +%Y%m%d-%H%M%S).json"
    cp -p "$CFG" "$BK"; chmod 600 "$BK"
    ok "Backed up the Claude config to $BK"
  fi
}
# edit_cfg set|remove NAME: changes ONLY that entry; the file is replaced only after it parses back
edit_cfg() {
  CFG="$CFG" NAME="$2" ACTION="$1" INST="$INST" SERVER_PY="$SERVER_PY" ENV_PREFIX="$ENV_PREFIX" "$PY" -I - <<'PY'
import json, os, tempfile
p, name, action, inst = os.environ["CFG"], os.environ["NAME"], os.environ["ACTION"], os.environ["INST"]
try:
    with open(p) as f:
        cfg = json.load(f)
except FileNotFoundError:
    cfg = {}
except json.JSONDecodeError as e:
    raise SystemExit(f"  The Claude config isn't valid JSON ({e}); not touching it.")
servers = cfg.setdefault("mcpServers", {})
before = sorted(servers)
if action == "set":
    entry = {"command": "/usr/bin/python3", "args": ["-I", "-B", f"{inst}/{os.environ['SERVER_PY']}"],
             "env": {f"{os.environ['ENV_PREFIX']}_POLICY": f"{inst}/policy.json"}}
    what = "unchanged" if servers.get(name) == entry else ("replaced" if name in servers else "added")
    servers[name] = entry
else:
    what = "removed" if servers.pop(name, None) is not None else "was not there"
os.makedirs(os.path.dirname(p), exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), prefix=".cfg-")
with os.fdopen(fd, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
json.load(open(tmp))
os.replace(tmp, p)
after = sorted(json.load(open(p))["mcpServers"])
lost = set(before) - set(after) - {name}
if lost:
    raise SystemExit(f"  Lost entries {sorted(lost)}?! Restore the backup.")
print(f"  \033[32m✓\033[0m {name} entry {what}; servers now: {', '.join(after)}")
PY
}
has_entry() {  # has_entry NAME: is there such an entry in the Claude config?
  CFG="$CFG" NAME="$1" "$PY" -I -c 'import json,os,sys
try:
    s = json.load(open(os.environ["CFG"])).get("mcpServers", {})
except (FileNotFoundError, ValueError):
    s = {}
sys.exit(0 if os.environ["NAME"] in s else 1)'
}
old_install() {  # what is left of Mac Ops (0.6 and before); changes nothing
  local any=0
  has_entry "$OLD_NAME" && { warn "Old $OLD_TITLE entry \"$OLD_NAME\" in the Claude config: installing replaces it"; any=1; }
  [ -d "$OLD_INST" ] && { warn "Old $OLD_TITLE copy at $OLD_INST: installing removes it"; any=1; }
  [ -d "$OLD_STATE" ] && { ok "Old $OLD_TITLE state (audit log): $OLD_STATE. Kept; delete it when you no longer need it"; any=1; }
  if [ -n "$TMUX_BIN" ] && "$TMUX_BIN" -L "$OLD_SOCKET" ls >/dev/null 2>&1; then
    warn "tmux sessions on the old socket '$OLD_SOCKET' ($OLD_TITLE used it; not touched): tmux -L $OLD_SOCKET ls"; any=1
  fi
  [ "$any" = 1 ] || ok "No old $OLD_TITLE install"
}

# ------------------------------------------------------------------ --check --
if [ "$MODE" = check ]; then
  say "Checking $TITLE (no changes)"
  ok "Python: $PY ($("$PY" -I -c 'import platform; print(platform.python_version())'))"
  [ -n "$TMUX_BIN" ] && ok "tmux: $TMUX_BIN ($("$TMUX_BIN" -V))" || warn "No tmux: sessions need it (brew install tmux)"
  ok "policy: $POLICY_SRC"
  ok "protected folders (never writable in the fence): $PROTECTED"
  say "Installed copy ($INST)"
  if [ ! -d "$INST" ]; then
    warn "Not installed yet: run this script without --check"
  else
    if cmp -s "$HERE/$SERVER_PY" "$INST/$SERVER_PY"; then ok "$SERVER_PY matches this folder"
    else warn "$SERVER_PY differs from this folder: review (git diff), then re-run without --check"; fi
    [ -f "$INST/INSTALLED" ] && ok "installed from: $(cat "$INST/INSTALLED")"
  fi
  say "Claude config"
  CFG="$CFG" NAME="$NAME" INST="$INST" SERVER_PY="$SERVER_PY" "$PY" -I - <<'PY'
import json, os
try:
    servers = json.load(open(os.environ["CFG"])).get("mcpServers", {})
except FileNotFoundError:
    servers = {}
n = os.environ["NAME"]
e = servers.get(n)
if not e:
    print(f"  \033[33m!\033[0m No {n} entry: run this script without --check")
elif f"{os.environ['INST']}/{os.environ['SERVER_PY']}" in e.get("args", []):
    print(f"  \033[32m✓\033[0m {n} entry present: {e.get('command')} {' '.join(e.get('args', []))}")
else:
    print(f"  \033[33m!\033[0m {n} runs something else: {e.get('command')} {e.get('args')}")
print("    servers in config:", ", ".join(sorted(servers)) or "none")
PY
  say "State ($STATE)"
  [ -f "$STATE/audit.jsonl" ] && ok "Audit log: $STATE/audit.jsonl ($(wc -l < "$STATE/audit.jsonl" | tr -d ' ') lines)" || ok "Audit log: created on first use"
  CPID="$("$PY" -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("pid",""))' "$STATE/caffeinate.json" 2>/dev/null || true)"
  if [ -n "$CPID" ] && ps -p "$CPID" -o comm= 2>/dev/null | grep -q caffeinate; then ok "keep_awake: on (caffeinate pid $CPID)"; else ok "keep_awake: off"; fi
  if [ -n "$TMUX_BIN" ] && "$TMUX_BIN" -L "$SOCKET" ls >/dev/null 2>&1; then
    ok "sessions (tmux -L $SOCKET attach -t <name>):"; "$TMUX_BIN" -L "$SOCKET" ls | sed 's/^/      /'
  else
    ok "sessions: none"
  fi
  say "Old $OLD_TITLE install (0.6 and before)"
  old_install
  exit 0
fi

# ----------------------------------------------------------------- --remove --
if [ "$MODE" = remove ]; then
  quit_claude
  say "Removing the $NAME entry"
  backup_cfg
  edit_cfg remove "$NAME"
  if [ -d "$INST" ]; then chmod -R u+w "$INST" && rm -rf "$INST" && ok "Removed $INST"; fi
  ok "Kept $STATE (audit log, job results). Running tmux sessions are not touched: tmux -L $SOCKET ls"
  { has_entry "$OLD_NAME" || [ -d "$OLD_INST" ]; } && warn "An old $OLD_TITLE install is still there (bash install.sh --check shows it); not touched"
  exit 0
fi

# ------------------------------------------------------------------ install --
say "Checks"
ok "Python: $PY ($("$PY" -I -c 'import platform; print(platform.python_version())'))"
[ -n "$TMUX_BIN" ] && ok "tmux: $TMUX_BIN" || warn "No tmux: the session tools will refuse until you brew install tmux"

if [ "$TESTS" = 1 ]; then
  say "Tests"
  if [ -z "$TMUX_BIN" ]; then
    warn "Skipped: they need tmux"
  elif (cd "$HERE" && PATH="$(dirname "$TMUX_BIN"):$PATH" "$PY" -B -m unittest discover -s tests >"${TMPDIR:-/tmp}/$NAME-tests.log" 2>&1); then
    ok "$(tail -n 1 "${TMPDIR:-/tmp}/$NAME-tests.log")"
  else
    tail -n 30 "${TMPDIR:-/tmp}/$NAME-tests.log"
    die "Tests failed (above; full log ${TMPDIR:-/tmp}/$NAME-tests.log). Nothing was installed."
  fi
fi

quit_claude

say "Installing the read-only copy to $INST"
mkdir -p "$INST"; chmod 700 "$DEST" "$INST"
[ -f "$INST/$SERVER_PY" ] && chmod u+w "$INST"/* 2>/dev/null || true
install -m 444 "$HERE/$SERVER_PY" "$INST/$SERVER_PY"
TMUX_BIN="$TMUX_BIN" "$PY" -I - "$POLICY_SRC" "$INST/policy.json.tmp" <<'PY'
import json, os, sys
pol = json.load(open(sys.argv[1]))
if os.environ.get("TMUX_BIN"):
    pol["tmux"] = os.environ["TMUX_BIN"]
with open(sys.argv[2], "w") as f:
    json.dump(pol, f, indent=2)
    f.write("\n")
PY
install -m 444 "$INST/policy.json.tmp" "$INST/policy.json" && rm -f "$INST/policy.json.tmp"
GITSHA="$(GIT_OPTIONAL_LOCKS=0 git -C "$HERE" rev-parse --short=12 HEAD 2>/dev/null || echo 'no-git')"
DIRTY=clean; [ -n "$(GIT_OPTIONAL_LOCKS=0 git -C "$HERE" status --porcelain -- "$SERVER_PY" policy.json 2>/dev/null)" ] && DIRTY=dirty
printf 'commit %s %s %s sha256:%s at %s\n' "$GITSHA" "$DIRTY" "$SERVER_PY" \
  "$(shasum -a 256 "$HERE/$SERVER_PY" | cut -c1-12)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$INST/INSTALLED.tmp"
install -m 444 "$INST/INSTALLED.tmp" "$INST/INSTALLED" && rm -f "$INST/INSTALLED.tmp"
[ "$DIRTY" = dirty ] && warn "Installed from uncommitted files (git status): commit them so the history shows what runs"
printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | env "${ENV_PREFIX}_POLICY=$INST/policy.json" "$PY" -I -B "$INST/$SERVER_PY" \
  | NAME="$NAME" "$PY" -I -c 'import json,os,sys; r=[json.loads(x) for x in sys.stdin]; assert r[0]["result"]["serverInfo"]["name"]==os.environ["NAME"]; print(len(r[1]["result"]["tools"]))' \
  > "$INST/.handshake" 2>&1 || die "The installed server did not answer the MCP handshake."
ok "Installed; the server answers with $(cat "$INST/.handshake") tools"; rm -f "$INST/.handshake"
SANDBOX_FAIL="$("$PY" -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sandbox_fail", "refuse"))' "$INST/policy.json")"
if ST="$(env "${ENV_PREFIX}_POLICY=$INST/policy.json" "$PY" -I -B "$INST/$SERVER_PY" --selftest 2>&1)"; then
  ok "The fence (macOS sandbox) works here. $ST"
elif [ "$SANDBOX_FAIL" = unsandboxed ]; then
  warn "The sandbox self-test failed: $ST. Shell commands will run UNSANDBOXED (policy sandbox_fail: unsandboxed)."
else
  warn "The sandbox self-test failed: $ST. Shell commands will be refused until it passes (policy sandbox_fail: refuse); the file tools work. Claude can show why with status."
fi

say "Adding the server to the Claude desktop config"
backup_cfg
edit_cfg set "$NAME"
if has_entry "$OLD_NAME"; then
  edit_cfg remove "$OLD_NAME"
  ok "($TITLE replaces $OLD_TITLE: the old \"$OLD_NAME\" entry is gone)"
fi
if [ -d "$OLD_INST" ] && [ "$(basename "$OLD_INST")" = "$OLD_NAME" ]; then          # that folder only
  chmod -R u+w "$OLD_INST" && rm -rf "$OLD_INST" && ok "Removed the old $OLD_TITLE copy at $OLD_INST"
fi
if [ -d "$OLD_STATE" ]; then
  ok "Kept the old $OLD_TITLE state folder, with its audit log: $OLD_STATE (delete it when you no longer need it)"
fi
if [ -n "$TMUX_BIN" ] && "$TMUX_BIN" -L "$OLD_SOCKET" ls >/dev/null 2>&1; then
  warn "tmux sessions still run on the old socket '$OLD_SOCKET' ($OLD_TITLE's; not touched): tmux -L $OLD_SOCKET ls"
fi

say "Done"
echo "  No dialogs. Shell commands run in the fence (a macOS sandbox): they can't read ~/.ssh, ~/.aws or the Keychain,"
echo "  can't write outside your home folder, and can't change shell rc files, LaunchAgents, .git hooks or Claude's"
echo "  config. What the fence blocks, Claude can rerun with outside_sandbox and a why: logged, never silent."
echo "  Claude can show the state with status."
echo "  Watch Claude's sessions: tmux -L $SOCKET ls    then    tmux -L $SOCKET attach -t <name>   (detach: Ctrl-b d)"
echo "  Audit log: $STATE/audit.jsonl"
[ "${REOPEN:-0}" = 1 ] || echo "  Restart Claude (Cmd+Q, then open it) to load the server."
