"""By hand, on a Mac: what the fence (Mac Ops' one sandbox profile, v0.7) blocks and allows here, probe by probe,
beyond what the self-test proves at every start. Run it unsandboxed, in Terminal:

    /usr/bin/python3 -I -B tests/fence_probe.py

It uses the policy next to the server (policy.local.json if present, else policy.json; or MAC_OPS_POLICY) and the
extra guards this Mac's self-test accepts. It creates only probe files with a random tag (in the home folder, temp, a
scratch repo under ~/.local/state, and, if the fence failed, /Users/Shared or ~/Library/LaunchAgents) and removes
them at the end. Calculator may start hidden for a second (the open probes). It prints a table: 'yes' is what the
fence should do. (It replaces the 0.3.2 comparison with sandbox-runtime's profiles, which tested the read and grant
profiles that 0.7 no longer has; that script is in the 0.6.0 history.)
"""
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
for name in ("policy.local.json", "policy.json"):
    if os.path.exists(os.path.join(ROOT, name)):
        os.environ.setdefault("MAC_OPS_POLICY", os.path.join(ROOT, name))
        break
import mac_ops_server as M  # noqa: E402

q = shlex.quote
MACH_PY = ("import ctypes, sys\nlibc = ctypes.CDLL('/usr/lib/libSystem.B.dylib')\n"
           "bp = ctypes.c_uint.in_dll(libc, 'bootstrap_port')\n"
           "libc.bootstrap_look_up.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]\n"
           "for n in sys.argv[1:]:\n port = ctypes.c_uint(0)\n"
           " print('MACH', n, libc.bootstrap_look_up(bp.value, n.encode(), ctypes.byref(port)))\n")


def main():
    P = M.policy()
    if sys.platform != "darwin":
        sys.exit("macOS only")
    st = M._selftest()
    print(f"mac-ops {M.VERSION}, policy {P['_path']}: self-test", "PASS" if st["ok"] else "FAIL " + st["reason"],
          "| extras:", st["extras"])
    prof = M.sb_profile(extras=st["extras"] if st["ok"] else [])
    H, tag = M.home(), f"{os.getpid()}-{os.urandom(3).hex()}"
    repo = os.path.realpath(P["state_dir"]) + f"-probe-{tag}"
    junk = [os.path.join(H, f".mac-ops-probe-{tag}"), f"/Users/Shared/.mac-ops-probe-{tag}",
            os.path.join(H, "Library", "LaunchAgents", f".mac-ops-probe-{tag}"), f"/private/tmp/mac-ops-probe-{tag}"]
    tmux = M.tmux_exe()
    junk.append(tmux + f".mac-ops-probe-{tag}")
    r = {}

    def run(argv, cwd=H, timeout=25):
        rc, out, _, _ = M.via_tmux([P["sandbox_exec"], "-f", M.sb_file(prof)] + argv, cwd, timeout, merge=True)
        return rc, out

    def sh(script, cwd=H):
        return run(["/bin/sh", "-c", script], cwd)

    def pgrep(name):
        return subprocess.run(["/usr/bin/pgrep", "-x", name], capture_output=True).returncode == 0
    sleeper = subprocess.Popen(["/bin/sleep", "120"])
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    conn = ("import socket\ntry:\n socket.create_connection(('127.0.0.1', %d), 3); print('CONN' + 'ECTED')\n"
            "except Exception as e:\n print('BLOCK' + 'ED', type(e).__name__)" % srv.getsockname()[1])
    try:
        os.makedirs(repo)
        subprocess.run(f"cd {q(repo)} && git init -q && git -c user.email=e@x -c user.name=n commit -q "
                       "--allow-empty -m init", shell=True, check=True)
        rc, out = run(["/bin/zsh", "-l", "-c", "echo shell-ok; git --version >/dev/null 2>&1 && echo git-ok"])
        r["login shell starts, git runs"] = "shell-ok" in out and "git-ok" in out
        sh(f"touch {q(junk[0])}")
        r["home folder writable"] = os.path.exists(junk[0])
        sh(f"touch {q(junk[3])}")
        r["temp writable"] = os.path.exists(junk[3])
        if os.path.isdir("/Users/Shared"):
            sh(f"touch {q(junk[1])}")
            r["outside home refused (/Users/Shared)"] = not os.path.exists(junk[1])
        if os.path.isdir(os.path.dirname(junk[2])):
            sh(f"touch {q(junk[2])}")
            r["~/Library/LaunchAgents refused"] = not os.path.exists(junk[2])
        sh(f"touch {q(junk[4])}")
        r[f"next to tmux ({os.path.dirname(tmux)}) refused"] = not os.path.exists(junk[4])
        sh("touch .git/hooks/x; mkdir -p .vscode .claude; echo x > .vscode/tasks.json; echo x > .mcp.json; "
           "echo x > .claude/settings.json; echo x > .claude.json; echo x > .envrc", repo)
        for rel in (".git/hooks/x", ".vscode/tasks.json", ".mcp.json", ".claude/settings.json", ".claude.json",
                    ".envrc"):
            r[f"{rel} refused"] = not os.path.exists(os.path.join(repo, rel))
        sh("mv .git .git-x && mkdir -p .git-x/hooks && echo evil > .git-x/hooks/post-commit && mv .git-x .git", repo)
        r["hooks can't come back by renaming .git"] = not os.path.exists(os.path.join(repo, ".git", "hooks",
                                                                                      "post-commit"))
        if os.path.isdir(os.path.join(repo, ".git-x")) and not os.path.exists(os.path.join(repo, ".git")):
            os.rename(os.path.join(repo, ".git-x"), os.path.join(repo, ".git"))
        rc, out = sh("echo a >> f && git add f && git -c user.email=e@x -c user.name=n commit -qm t && echo commit-ok",
                     repo)
        r["git add + commit work"] = "commit-ok" in out
        if os.path.isdir(os.path.join(H, ".ssh")):
            rc, out = sh("ls ~/.ssh >/dev/null 2>&1; echo ls-rc=$?; ls ~/.SSH >/dev/null 2>&1; echo LS-rc=$?")
            r["~/.ssh unreadable (and ~/.SSH)"] = "ls-rc=0" not in out and "LS-rc=0" not in out
        if os.path.exists(M.state_path("audit.jsonl")):
            rc, out = sh(f"head -c 20 {q(M.state_path('audit.jsonl'))} >/dev/null 2>&1; echo cat-rc=$?")
            r["the audit log unreadable"] = "cat-rc=0" not in out
        rc, out = run([sys.executable, "-I", "-c", conn])
        r[f"network {'connects' if P['network'] else 'refused'} (policy network: {P['network']})"] = (
            ("CONNECTED" if P["network"] else "BLOCKED") in out)
        rc, out = sh("for p in osascript open security defaults pbpaste launchctl; do command -v $p >/dev/null && "
                     "$(command -v $p) >/dev/null 2>&1; echo $p-rc=$?; done")
        for p in ("osascript", "open", "security", "defaults", "pbpaste", "launchctl"):
            r[f"{p} can't start"] = f"{p}-rc=126" in out
        copy = f"/private/tmp/mac-ops-probe-open-{tag}"
        junk.append(copy)
        shutil.copyfile("/usr/bin/open", copy)
        os.chmod(copy, 0o755)
        for what, prog in (("a copy of open", copy), ("OPEN in other case", "/USR/BIN/OPEN")):
            if pgrep("Calculator"):
                break
            sh(f"{q(prog)} -g -j -a Calculator >/dev/null 2>&1")
            time.sleep(2)
            launched = pgrep("Calculator")
            if launched:
                subprocess.run(["/usr/bin/pkill", "-x", "Calculator"])
                time.sleep(1)
            r[f"{what} can't launch an app"] = not launched
        rc, out = run([sys.executable, "-I", "-c", MACH_PY, "com.apple.SecurityServer", "com.apple.pasteboard.1"])
        for ln in out.splitlines():
            if ln.startswith("MACH "):
                _, n, kr = ln.split()
                r[f"mach {n} unreachable"] = kr != "0"
        sh(f"kill {sleeper.pid}")
        time.sleep(0.2)
        r["can't kill a process outside"] = sleeper.poll() is None
        rc, out = run([sys.executable, "-I", "-c", "import socket\ntry:\n socket.getaddrinfo('example.com', 443); "
                                                    "print('DNS-' + 'OK')\nexcept Exception:\n print('DNS-' + 'NO')"])
        print("(DNS lookups from the fence: " + ("answered" if "DNS-OK" in out else "not answered") + "; the profile "
              "doesn't close them)")
    finally:
        srv.close()
        if sleeper.poll() is None:
            sleeper.kill()
        for p in junk:
            try:
                os.remove(p)
            except OSError:
                pass
        shutil.rmtree(repo, ignore_errors=True)
    print("\n| probe | fence |\n|---|---|")
    for k, v in r.items():
        print(f"| {k} | {'yes' if v else 'NO'} |")
    print(f"\n{sum(r.values())}/{len(r)} as expected")


if __name__ == "__main__":
    main()
