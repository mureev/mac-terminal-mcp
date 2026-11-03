#!/bin/bash
# Installs Mac Ops ("mac-ops") in the Claude desktop app: Claude's shell, sessions and files on this Mac. It reaches no
# remote host (ssh, scp, ansible are denied). Approvals are tiered (v0.3): reads run in a
# read-only macOS sandbox without asking, one dialog opens a grant for a task, and pushes and the like always ask.
#
#   bash install.sh                install, or update to what this folder holds now (review `git diff` first)
#   bash install.sh --check        change nothing: installed copy vs this folder, the Claude entry, tmux,
#                                  the audit log, keep_awake, the sessions
#   bash install.sh --remove       remove the mac-ops entry and the installed copy (keeps ~/.local/state/mac-ops)
#   bash install.sh --skip-tests   install without running the tests first
#
# Why a copy. This folder is writable by every Claude session connected to it. If Claude desktop ran the server from
# here, any session could change what the next call runs. So this script copies mac_ops_server.py and policy.json to
# ~/.config/claude-mcp/mac-ops/ (read-only files), and Claude desktop runs that copy with the system Python
# (/usr/bin/python3 -I -B). Updating = review the diff, commit, run this script again. No package manager is involved:
# the server is one file of Python's standard library, so nothing changes under you between updates.
#
# What it does, in order:
#   1. Checks /usr/bin/python3 (3.9 or newer), tmux (brew install tmux) and policy.json.
#   2. Runs the tests (tmux sessions on a test socket, temporary folders; nothing outside them is touched).
#   3. Quits Claude while its config is edited, so the app can't write an older copy back. Reopens it at the end.
#   4. Installs the read-only copy (policy.json gets tmux's full path), checks it answers the MCP handshake, and
#      runs the sandbox self-test (if it fails, the server asks for every call, as in v0.2; nothing else changes).
#   5. Backs up claude_desktop_config.json to ~/.config/claude-mcp/backups/, then adds or replaces ONLY the mac-ops
#      entry. Every other entry is kept; the result is parsed back before it replaces the file.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
NAME="mac-ops"
DEST="${MCP_DEST:-$HOME/.config/claude-mcp}"
INST="$DEST/$NAME"
STATE="$HOME/.local/state/mac-ops"
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
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "Unknown argument '$a'. Use --check, --remove, --skip-tests, or nothing to install." ;;
  esac
done

[ -x "$PY" ] || die "No $PY. Install the Xcode command line tools (xcode-select --install)."
"$PY" -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "$PY is older than 3.9. Update the Xcode command line tools (xcode-select --install)."
TMUX_BIN="$(command -v tmux || true)"
for c in /opt/homebrew/bin/tmux /usr/local/bin/tmux; do [ -z "$TMUX_BIN" ] && [ -x "$c" ] && TMUX_BIN="$c"; done
# A policy.local.json next to policy.json (git-ignored) is installed instead of it: this Mac's own folders and paths.
POLICY_SRC="$HERE/policy.json"; [ -f "$HERE/policy.local.json" ] && POLICY_SRC="$HERE/policy.local.json"
PROTECTED="$("$PY" -I -c 'import json,os,sys; print(", ".join(os.path.expanduser(x) for x in json.load(open(sys.argv[1])).get("protected_folders", [])) or "none")' "$POLICY_SRC")"

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
# edit_cfg set|remove: changes ONLY the mac-ops entry; the file is replaced only after it parses back
edit_cfg() {
  CFG="$CFG" NAME="$NAME" ACTION="$1" INST="$INST" "$PY" -I - <<'PY'
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
    entry = {"command": "/usr/bin/python3", "args": ["-I", "-B", f"{inst}/mac_ops_server.py"],
             "env": {"MAC_OPS_POLICY": f"{inst}/policy.json"}}
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

# ------------------------------------------------------------------ --check --
if [ "$MODE" = check ]; then
  say "Checking Mac Ops (no changes)"
  ok "Python: $PY ($("$PY" -I -c 'import platform; print(platform.python_version())'))"
  [ -n "$TMUX_BIN" ] && ok "tmux: $TMUX_BIN ($("$TMUX_BIN" -V))" || warn "No tmux: sessions need it (brew install tmux)"
  ok "policy: $POLICY_SRC"
  ok "protected folders (never a grant folder): $PROTECTED"
  say "Installed copy ($INST)"
  if [ ! -d "$INST" ]; then
    warn "Not installed yet: run this script without --check"
  else
    if cmp -s "$HERE/mac_ops_server.py" "$INST/mac_ops_server.py"; then ok "mac_ops_server.py matches this folder"
    else warn "mac_ops_server.py differs from this folder: review (git diff), then re-run without --check"; fi
    [ -f "$INST/INSTALLED" ] && ok "installed from: $(cat "$INST/INSTALLED")"
  fi
  say "Claude config"
  CFG="$CFG" NAME="$NAME" INST="$INST" "$PY" -I - <<'PY'
import json, os
try:
    servers = json.load(open(os.environ["CFG"])).get("mcpServers", {})
except FileNotFoundError:
    servers = {}
e = servers.get(os.environ["NAME"])
if not e:
    print("  \033[33m!\033[0m No mac-ops entry: run this script without --check")
elif f"{os.environ['INST']}/mac_ops_server.py" in e.get("args", []):
    print(f"  \033[32m✓\033[0m mac-ops entry present: {e.get('command')} {' '.join(e.get('args', []))}")
else:
    print(f"  \033[33m!\033[0m mac-ops runs something else: {e.get('command')} {e.get('args')}")
print("    servers in config:", ", ".join(sorted(servers)) or "none")
PY
  say "State ($STATE)"
  [ -f "$STATE/audit.jsonl" ] && ok "Audit log: $STATE/audit.jsonl ($(wc -l < "$STATE/audit.jsonl" | tr -d ' ') lines)" || ok "Audit log: created on first use"
  CPID="$("$PY" -I -c 'import json,sys; print(json.load(open(sys.argv[1])).get("pid",""))' "$STATE/caffeinate.json" 2>/dev/null || true)"
  if [ -n "$CPID" ] && ps -p "$CPID" -o comm= 2>/dev/null | grep -q caffeinate; then ok "keep_awake: on (caffeinate pid $CPID)"; else ok "keep_awake: off"; fi
  if [ -n "$TMUX_BIN" ] && "$TMUX_BIN" -L claude ls >/dev/null 2>&1; then
    ok "sessions (tmux -L claude attach -t <name>):"; "$TMUX_BIN" -L claude ls | sed 's/^/      /'
  else
    ok "sessions: none"
  fi
  exit 0
fi

# ----------------------------------------------------------------- --remove --
if [ "$MODE" = remove ]; then
  quit_claude
  say "Removing the mac-ops entry"
  backup_cfg
  edit_cfg remove
  if [ -d "$INST" ]; then chmod -R u+w "$INST" && rm -rf "$INST" && ok "Removed $INST"; fi
  ok "Kept $STATE (audit log, job results). Running tmux sessions are not touched: tmux -L claude ls"
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
  elif (cd "$HERE" && PATH="$(dirname "$TMUX_BIN"):$PATH" "$PY" -B -m unittest discover -s tests >"${TMPDIR:-/tmp}/mac-ops-tests.log" 2>&1); then
    ok "$(tail -n 1 "${TMPDIR:-/tmp}/mac-ops-tests.log")"
  else
    tail -n 30 "${TMPDIR:-/tmp}/mac-ops-tests.log"
    die "Tests failed (above; full log ${TMPDIR:-/tmp}/mac-ops-tests.log). Nothing was installed."
  fi
fi

quit_claude

say "Installing the read-only copy to $INST"
mkdir -p "$INST"; chmod 700 "$DEST" "$INST"
[ -f "$INST/mac_ops_server.py" ] && chmod u+w "$INST"/* 2>/dev/null || true
install -m 444 "$HERE/mac_ops_server.py" "$INST/mac_ops_server.py"
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
DIRTY=clean; [ -n "$(GIT_OPTIONAL_LOCKS=0 git -C "$HERE" status --porcelain -- mac_ops_server.py policy.json 2>/dev/null)" ] && DIRTY=dirty
printf 'commit %s %s mac_ops_server.py sha256:%s at %s\n' "$GITSHA" "$DIRTY" \
  "$(shasum -a 256 "$HERE/mac_ops_server.py" | cut -c1-12)" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$INST/INSTALLED.tmp"
install -m 444 "$INST/INSTALLED.tmp" "$INST/INSTALLED" && rm -f "$INST/INSTALLED.tmp"
[ "$DIRTY" = dirty ] && warn "Installed from uncommitted files (git status): commit them so the history shows what runs"
printf '%s\n%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | MAC_OPS_POLICY="$INST/policy.json" "$PY" -I -B "$INST/mac_ops_server.py" \
  | "$PY" -I -c 'import json,sys; r=[json.loads(x) for x in sys.stdin]; assert r[0]["result"]["serverInfo"]["name"]=="mac-ops"; print(len(r[1]["result"]["tools"]))' \
  > "$INST/.handshake" 2>&1 || die "The installed server did not answer the MCP handshake."
ok "Installed; the server answers with $(cat "$INST/.handshake") tools"; rm -f "$INST/.handshake"
if ST="$(MAC_OPS_POLICY="$INST/policy.json" "$PY" -I -B "$INST/mac_ops_server.py" --selftest 2>&1)"; then
  ok "Approvals: tiers. $ST"
else
  warn "Approvals: every call asks (v0.2), because the sandbox self-test failed: $ST"
fi

say "Adding the server to the Claude desktop config"
backup_cfg
edit_cfg set

say "Done"
echo "  Reads run in a read-only sandbox without asking. A task asks once (request_grant: folders, minutes, network);"
echo "  pushes, cloud CLIs, uploads, launchd, settings, and install.sh always ask. Claude can show the"
echo "  state with approval_status."
echo "  Watch Claude's sessions: tmux -L claude ls    then    tmux -L claude attach -t <name>   (detach: Ctrl-b d)"
echo "  Audit log: $STATE/audit.jsonl"
[ "${REOPEN:-0}" = 1 ] || echo "  Restart Claude (Cmd+Q, then open it) to load the server."
