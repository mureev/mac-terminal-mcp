"""By-hand experiment, 2026-11-01: mac-ops's own Seatbelt profiles next to the ones Anthropic's sandbox-runtime
(@anthropic-ai/sandbox-runtime 0.0.81, the engine of Claude Code's sandbox) generates for the same tiers.

sandbox-runtime never runs on this Mac: its profiles were generated in Claude's cloud sandbox from the npm package
(sha256 0e0b8249...953f) and saved as data in srt-0.0.81-profiles.json (the home folder as __HOME__). This script, run unsandboxed on the Mac:
  1. runs mac-ops's self-test with each profile, and two self-tests at once (the v0.3.2 race fix);
  2. runs the same probes under each profile: what tier-0 reads need, and what the self-test doesn't cover
     (renaming .git, case tricks, DNS, mach services, open launching an app, editor/MCP config files);
  3. prints a table. It changes nothing outside ~/.local/state/mac-ops-exp-*, temp and one probe file in
     ~/.config/claude-mcp, all removed at the end. Calculator may start hidden for a second (the open probe).

    /usr/bin/python3 -I -B tests/sandbox_runtime_experiment.py
"""
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("MAC_OPS_POLICY", os.path.join(ROOT, "policy.json"))
import mac_ops_server as M  # noqa: E402

P = M.policy()
H = M.home()
SBX = P["sandbox_exec"]
STATE_PARENT = os.path.dirname(os.path.realpath(P["state_dir"]))
SRT = json.load(open(os.path.join(ROOT, "tests", "srt-0.0.81-profiles.json")))
ORIG = M.sb_profile
q = shlex.quote


def vf() -> str:
    t = subprocess.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True).stdout.strip()
    t = os.path.realpath(t)
    assert t.startswith("/private/var/folders/") and t.endswith("/T"), t
    return t[len("/private/var/folders/"):-2]


VF = vf()


def load_031():
    """v0.3.1 as installed today, from git (its server and policy), for its sb_profile."""
    import importlib.util
    import tempfile
    d = tempfile.mkdtemp(prefix="mac-ops-031-")
    for f in ("mac_ops_server.py", "policy.json"):
        src = subprocess.run(["git", "-C", ROOT, "show", f"c773f20:{f}"], capture_output=True, check=True).stdout
        with open(os.path.join(d, f), "wb") as fh:
            fh.write(src)
    saved = os.environ["MAC_OPS_POLICY"]
    os.environ["MAC_OPS_POLICY"] = os.path.join(d, "policy.json")
    try:
        spec = importlib.util.spec_from_file_location("mac_ops_031", os.path.join(d, "mac_ops_server.py"))
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        m.policy()
    finally:
        os.environ["MAC_OPS_POLICY"] = saved
    return m


def macops(sb_profile, base_extras):
    def fn(mode, g=None, extras=None):
        return sb_profile(mode, g, extras=base_extras if extras is None else extras)
    return fn


def srt(variant):
    prof = SRT[variant]

    def fn(mode, g=None, extras=None):
        if mode == "read":
            p = prof["read"]
        else:
            p = prof["grant_net" if g.get("network") else "grant"]
            gd = g["folders"][0]
            assert os.path.dirname(gd) == STATE_PARENT, gd
            p = p.replace("__GDIR__", os.path.basename(gd))
        return p.replace("__HOME__", H).replace("__VF__", VF) + "".join("\n" + M.SB_EXTRAS[x] for x in (extras or []))
    return fn


def run(profile, argv, cwd=H, timeout=25):
    rc, out, _, _ = M.via_tmux([SBX, "-f", M.sb_file(profile)] + argv, cwd, timeout, merge=True)
    return rc, out


def sh(profile, script, cwd=H):
    return run(profile, ["/bin/sh", "-c", script], cwd)


def pgrep(name):
    return subprocess.run(["/usr/bin/pgrep", "-x", name], capture_output=True).returncode == 0


MACH = ("com.apple.SecurityServer", "com.apple.securityd.xpc", "com.apple.pasteboard.1",
        "com.apple.coreservices.appleevents", "com.apple.coreservices.launchservicesd",
        "com.apple.CoreServices.coreservicesd", "com.apple.cfprefsd.daemon", "com.apple.cfprefsd.agent",
        "com.apple.tccd", "com.apple.windowserver.active")
MACH_PY = ("import ctypes, sys\nlibc = ctypes.CDLL('/usr/lib/libSystem.B.dylib')\n"
           "bp = ctypes.c_uint.in_dll(libc, 'bootstrap_port')\n"
           "libc.bootstrap_look_up.argtypes = [ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint)]\n"
           "for n in sys.argv[1:]:\n port = ctypes.c_uint(0)\n"
           " print('MACH', n, libc.bootstrap_look_up(bp.value, n.encode(), ctypes.byref(port)))\n")


def battery(fn, label):
    tag = f"{os.getpid()}-{os.urandom(3).hex()}"
    r = {}
    gdir = os.path.join(STATE_PARENT, f"mac-ops-exp-{tag}")
    sub = os.path.join(gdir, "sub")
    secret_dir = os.path.join(H, ".config", "claude-mcp")
    secret = os.path.join(secret_dir, f"mac-ops-exp-secret-{tag}")
    state_secret = M.state_path("selftest", f"exp-{tag}", "s")
    junk = [os.path.join(H, f".mac-ops-exp-{tag}"), os.path.join(H, f".mac-ops-exp-g-{tag}"),
            f"/private/tmp/mac-ops-exp-{tag}", secret, os.path.join(H, ".npm", f"_mac-ops-exp-{tag}")]
    sleeper = subprocess.Popen(["/bin/sleep", "120"])
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)
    port = srv.getsockname()[1]
    conn = (f"import socket\ntry:\n socket.create_connection(('127.0.0.1', {port}), 3); print('CONN' + 'ECTED')\n"
            "except Exception as e:\n print('BLOCK' + 'ED', type(e).__name__)")
    try:
        os.makedirs(sub)
        for d in (gdir, sub):
            subprocess.run(f"cd {q(d)} && git init -q && git -c user.email=e@x -c user.name=n commit -q "
                           "--allow-empty -m init", shell=True, check=True)
        os.makedirs(secret_dir, exist_ok=True)
        with open(secret, "w") as f:
            f.write(f"exp-secret-{tag}\n")
        with open(state_secret, "w") as f:
            f.write(f"exp-state-{tag}\n")
        R = fn("read")
        G = fn("grant", {"folders": [gdir], "network": False})
        GN = fn("grant", {"folders": [gdir], "network": True})

        rc, out = run(R, ["/bin/zsh", "-l", "-c", "echo shell-ok; git --version >/dev/null 2>&1 && echo git-ok"])
        r["login shell starts"] = "shell-ok" in out
        r["git runs"] = "git-ok" in out
        rc, out = run(R, [sys.executable, "-I", "-c", "print('py-' + 'ok')"])
        r["program output comes back"] = "py-ok" in out
        sh(R, f"touch {q(junk[0])}")
        r["read: write to home refused"] = not os.path.exists(junk[0])
        sh(R, f"touch {q(junk[2])}")
        r["read: temp writable"] = os.path.exists(junk[2])
        rc, out = sh(R, f"cat {q(secret)}")
        r["read: denied folder unreadable"] = f"exp-secret-{tag}" not in out
        rc, out = sh(R, f"cat {q(secret.replace('/.config/claude-mcp/', '/.CONFIG/Claude-MCP/'))}")
        r["read: denied folder unreadable in OTHER CASE"] = f"exp-secret-{tag}" not in out
        rc, out = sh(R, f"cat {q(state_secret)}")
        r["read: mac-ops state (audit log, outputs) unreadable"] = f"exp-state-{tag}" not in out
        rc, out = run(R, [sys.executable, "-I", "-c", conn])
        r["read: network refused"] = "BLOCKED" in out
        rc, out = run(R, [sys.executable, "-I", "-c", "import socket\ntry:\n socket.getaddrinfo('example.com', 443)"
                                                      "; print('DNS-' + 'OK')\nexcept Exception as e:\n print('DNS-' + 'NO')"])
        r["read: DNS lookups refused"] = "DNS-NO" in out
        rc, out = sh(R, "/usr/bin/osascript -e 'return 7' >/dev/null 2>&1; echo osa-rc=$?")
        r["read: osascript can't run"] = "osa-rc=0" not in out
        copy = f"/private/tmp/mac-ops-exp-open-{tag}"
        junk.append(copy)
        shutil.copyfile("/usr/bin/open", copy)          # contents only: a system file's flags can't be copied
        os.chmod(copy, 0o755)
        for what, prog in (("open", "/usr/bin/open"), ("a copy of open", copy), ("OPEN in other case", "/USR/BIN/OPEN")):
            if pgrep("Calculator"):
                break
            sh(R, f"{q(prog)} -g -j -a Calculator >/dev/null 2>&1")
            time.sleep(2)
            launched = pgrep("Calculator")
            if launched:
                subprocess.run(["/usr/bin/pkill", "-x", "Calculator"])
                time.sleep(1)
            r[f"read: {what} can't launch an app"] = not launched
        rc, out = run(R, [sys.executable, "-I", "-c", MACH_PY] + list(MACH))
        for ln in out.splitlines():
            if ln.startswith("MACH "):
                _, n, kr = ln.split()
                r[f"read: mach {n} unreachable"] = kr != "0"
        sh(R, f"kill {sleeper.pid}")
        time.sleep(0.2)
        r["read: can't kill a process outside"] = sleeper.poll() is None
        rc, out = sh(R, "pbpaste >/dev/null 2>&1; echo pb-rc=$?")
        r["read: clipboard unreadable"] = "pb-rc=0" not in out
        for name, cmd in (("ps", "ps -ax | wc -l"), ("du", f"du -sh {q(ROOT)}"), ("find", f"find {q(ROOT)} -maxdepth 1"),
                          ("git log", f"git -C {q(ROOT)} log -1 --oneline"), ("ls ~/Library/Caches",
                                                                              "ls ~/Library/Caches | head -1"),
                          ("rg", "rg --version || /opt/homebrew/bin/rg --version"), ("sw_vers", "sw_vers")):
            rc, out = run(R, ["/bin/zsh", "-l", "-c", cmd])
            ok = rc == 0 and bool(out.strip())
            if name == "ps":
                ok = ok and out.strip().split()[-1].isdigit() and int(out.strip().split()[-1]) > 20
            r[f"tier 0 works: {name}"] = ok

        sh(G, "touch ok", gdir)
        r["grant: its folder writable"] = os.path.exists(os.path.join(gdir, "ok"))
        sh(G, f"touch {q(junk[1])}", gdir)
        r["grant: outside refused"] = not os.path.exists(junk[1])
        sh(G, "touch .git/hooks/x", gdir)
        r["grant: .git/hooks refused"] = not os.path.exists(os.path.join(gdir, ".git", "hooks", "x"))
        sh(G, "touch .GIT/hooks/y", gdir)
        r["grant: .git/hooks refused in OTHER CASE"] = not os.path.exists(os.path.join(gdir, ".git", "hooks", "y"))
        for where, d in (("its own .git", gdir), ("a nested repo's .git", sub)):
            sh(G, "mv .git .git-x && mkdir -p .git-x/hooks && echo evil > .git-x/hooks/post-commit && mv .git-x .git",
               d)
            r[f"grant: hooks can't come back by renaming {where}"] = not os.path.exists(
                os.path.join(d, ".git", "hooks", "post-commit"))
            if os.path.isdir(os.path.join(d, ".git-x")) and not os.path.exists(os.path.join(d, ".git")):
                os.rename(os.path.join(d, ".git-x"), os.path.join(d, ".git"))
        rc, out = sh(G, "echo a >> f && git add f && git -c user.email=e@x -c user.name=n commit -qm t && echo commit-ok",
                     gdir)
        r["grant: git add + commit work"] = "commit-ok" in out
        for name, rel in ((".vscode/tasks.json", ".vscode/tasks.json"), (".envrc", ".envrc"),
                          (".mcp.json", ".mcp.json"), (".gitmodules", ".gitmodules"),
                          (".claude/commands/x.md", ".claude/commands/x.md")):
            sh(G, f"mkdir -p $(dirname {q(rel)}) 2>/dev/null; echo x > {q(rel)}", gdir)
            r[f"grant: {name} refused"] = not os.path.exists(os.path.join(gdir, rel))
        sh(G, f"touch {q(junk[4])}", gdir)
        r["grant: build caches (~/.npm) writable"] = os.path.exists(junk[4])
        rc, out = run(G, [sys.executable, "-I", "-c", conn], gdir)
        r["grant: network refused without network"] = "BLOCKED" in out
        rc, out = run(GN, [sys.executable, "-I", "-c", conn], gdir)
        r["network grant: connects"] = "CONNECTED" in out
    finally:
        srv.close()
        if sleeper.poll() is None:
            sleeper.kill()
        for p in junk + [state_secret]:
            try:
                os.remove(p)
            except OSError:
                pass
        shutil.rmtree(gdir, ignore_errors=True)
        shutil.rmtree(os.path.dirname(state_secret), ignore_errors=True)
    return r


def selftest(fn):
    M.sb_profile = fn
    try:
        st = M._selftest()
    finally:
        M.sb_profile = ORIG
    return st


def main():
    print(f"macOS {subprocess.run(['sw_vers', '-productVersion'], capture_output=True, text=True).stdout.strip()}, "
          f"mac-ops {M.VERSION} (repo copy), Python {sys.version.split()[0]}")
    base = M._selftest()
    print("mac-ops self-test:", "PASS" if base["ok"] else "FAIL " + base["reason"], "| extras:", base["extras"])
    out = [None, None]

    def one(i):
        out[i] = M._selftest()
    ts = [threading.Thread(target=one, args=(i,)) for i in (0, 1)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    print("two self-tests at once:", ", ".join("PASS" if s["ok"] else "FAIL " + s["reason"] for s in out))
    extras = base["extras"] if base["ok"] else []
    m031 = load_031()
    profiles = [("mac-ops 0.3.1", macops(m031.sb_profile, [x for x in extras if x in m031.SB_EXTRAS])),
                ("mac-ops 0.3.2", macops(ORIG, extras)),
                ("srt 0.0.81", srt("srt")), ("srt +state", srt("srt+state"))]
    results, tests = {}, {}
    for label, fn in profiles:
        st = selftest(fn)
        tests[label] = "PASS" if st["ok"] else "FAIL: " + st["reason"][:150]
        results[label] = battery(fn, label)
    print("\nself-test with each profile:")
    for label, v in tests.items():
        print(f"  {label}: {v}")
    keys = list(dict.fromkeys(k for r in results.values() for k in r))
    print("\n| probe | " + " | ".join(results) + " |\n|---|" + "---|" * len(results))
    for k in keys:
        print(f"| {k} | " + " | ".join({True: "yes", False: "NO"}.get(r.get(k), "-") for r in results.values()) + " |")
    print("\nPython deny check, other case (read_file/run cwd): ", end="")
    for p in ("~/.SSH/id_ed25519", "~/.Aws/credentials", "~/Library/keychains/login.keychain-db"):
        try:
            M.path_arg({"path": p})
            print(f"{p}: NOT refused;", end=" ")
        except M.Refused:
            print(f"{p}: refused;", end=" ")
    print()
    json.dump({"selftest": tests, "probes": results}, open(os.path.join("/private/tmp", "mac-ops-srt-exp.json"), "w"),
              indent=1)
    print("\n[experiment done]")


if __name__ == "__main__":
    main()
