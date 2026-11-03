#!/bin/bash
# Seatbelt probe for mac-ops v0.3 (macOS, by hand or through mac-ops run). Creates only /private/tmp/mac-ops-spike and
# removes it. Answers: does /usr/bin/sandbox-exec, started inside tmux, block writes outside allowed folders, the
# network, Apple Events, LaunchServices, the clipboard, signals to other processes and reads of a denied folder, while
# zsh -l, git, python3 and Documents reads (tmux's privacy grant) still work?
set -u
S=/private/tmp/mac-ops-spike; rm -rf "$S"; mkdir -p "$S/allowed" "$S/secret"; echo topsecret > "$S/secret/k"
H="$HOME"; MO="$H/Documents/Claude/Projects/Mac Ops"
TMPD="$(cd "$(getconf DARWIN_USER_TEMP_DIR)" && pwd -P)"; CACHE="$(cd "$(getconf DARWIN_USER_CACHE_DIR)" && pwd -P)"
echo "macOS $(sw_vers -productVersion) $(uname -m); python $(/usr/bin/python3 -c 'import platform;print(platform.python_version())'); sandbox-exec: $(ls /usr/bin/sandbox-exec 2>&1); ${TMUX:+inside tmux}"
P="(version 1)
(allow default)
(deny network*)
(deny file-write*)
(allow file-write* (subpath \"$S/allowed\") (subpath \"$TMPD\") (subpath \"$CACHE\") (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/tty\") (regex #\"^/dev/fd/\") (regex #\"^/dev/ttys\"))
(deny file-read* (subpath \"$S/secret\"))
(deny appleevent-send)
(deny mach-lookup (global-name \"com.apple.coreservices.launchservicesd\") (global-name \"com.apple.pasteboard.1\") (global-name \"com.apple.cfprefsd.daemon\") (global-name \"com.apple.cfprefsd.agent\"))
(deny signal)
(allow signal (target same-sandbox))
"
sb() { /usr/bin/sandbox-exec -p "$P" "$@"; }
t() { local n="$1"; shift; local o; o="$("$@" 2>&1)"; local rc=$?; printf '%-26s rc=%-3s %s\n' "$n" "$rc" "$(printf '%s' "$o" | tr '\n' ' ' | cut -c1-120)"; }
t "true" sb /usr/bin/true
t "zsh -l" sb /bin/zsh -l -c 'echo zsh-ok'
t "ls Mac Ops (TCC)" sb /bin/ls "$MO"
t "git status" sb /usr/bin/env GIT_OPTIONAL_LOCKS=0 git -C "$MO" status --short
t "git log" sb git -C "$MO" log --oneline -1
t "python3" sb /usr/bin/python3 -c 'print("py-ok")'
t "write allowed" sb /usr/bin/touch "$S/allowed/x"
t "write TMPDIR" sb /usr/bin/touch "$TMPD/mac-ops-spike-x"
t "write Mac Ops (deny)" sb /usr/bin/touch "$MO/.spike-should-fail"
t "write home (deny)" sb /usr/bin/touch "$H/.mac-ops-spike-should-fail"
t "read secret (deny)" sb /bin/cat "$S/secret/k"
t "curl (deny)" sb /usr/bin/curl -sS -m 4 -o /dev/null -w '%{http_code}' https://example.com
t "py connect (deny)" sb /usr/bin/python3 -c 'import socket; socket.create_connection(("1.1.1.1",443),3); print("CONNECTED")'
t "py DNS resolve" sb /usr/bin/python3 -c 'import socket; print(socket.gethostbyname("example.com"))'
t "pbcopy (deny)" sb /bin/sh -c 'echo spike | pbcopy && echo copied'
t "defaults read" sb defaults read -g AppleLocale
t "osascript AE (deny)" sb /usr/bin/osascript -e 'tell application "Finder" to get name'
sleep 60 & V=$!
t "kill other (deny)" sb /bin/kill $V
kill $V 2>/dev/null; wait $V 2>/dev/null
t "kill own child" sb /bin/sh -c 'sleep 30 & kill $! && echo killed-own'
t "open app (deny)" sb /usr/bin/open -g -j -a Calculator
sleep 1; pgrep -x Calculator >/dev/null && { echo "  (Calculator launched; quitting it)"; pkill -x Calculator; }
t "launchctl list" sb /bin/sh -c 'launchctl list | head -1'
t "control: curl unsandboxed" /usr/bin/curl -sS -m 4 -o /dev/null -w '%{http_code}' https://example.com
s=$(/usr/bin/python3 -c 'import time;print(time.time())'); sb /usr/bin/true; e=$(/usr/bin/python3 -c 'import time;print(time.time())')
echo "overhead: $(/usr/bin/python3 -c "print(round(($e-$s)*1000))") ms"
rm -f "$MO/.spike-should-fail" "$H/.mac-ops-spike-should-fail" "$TMPD/mac-ops-spike-x"; rm -rf "$S"
