"""Tests for mac_terminal_mcp.py. Standard library only; they need tmux and git, and run on Linux or macOS:

    python3 -B -m unittest discover -s tests -v

The shell is bash here (tests must not depend on the Mac's zsh setup); macOS-only tools (keep_awake, notify, open)
are skipped elsewhere. Every test uses its own tmux socket and state directory. sandbox-exec is a stand-in that
records the fence's profile and runs the command; the real sandbox is tested on a Mac (MacSandbox).
"""
from __future__ import annotations

import json
import os
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import mac_terminal_mcp as M  # noqa: E402

SERVER_PY = os.path.join(ROOT, "mac_terminal_mcp.py")
HAVE_TMUX = shutil.which("tmux") is not None
ON_MAC = sys.platform == "darwin"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mac-terminal-test-")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.socket = f"mac-terminal-test-{os.getpid()}-{id(self) % 100000}"
        self.protected = os.path.join(self.tmp, "protected")
        self.prof = os.path.join(self.tmp, "profile")
        sbx = os.path.join(self.tmp, "fake-sandbox-exec")
        with open(sbx, "w") as f:
            f.write(f'#!/bin/bash\n[ "$1" = -f ] || exit 64\ncat "$2" > {self.prof!r}\nshift 2\nexec "$@"\n')
        os.chmod(sbx, 0o755)
        pol = {
            "shell": ["/bin/bash", "-c"],
            "session_shell": ["/bin/bash", "--norc", "--noprofile", "-i"],
            "tmux_socket": self.socket,
            "default_cwd": self.home,
            "state_dir": os.path.join(self.tmp, "state"),
            "protected_folders": [self.protected],
            "deny_paths": ["~/.ssh", os.path.join(self.tmp, "state"), os.path.join(self.tmp, "secret")],
            "sandbox_exec": sbx,
            "sandbox_selftest": False,
        }
        pol.update(self.policy_extra())
        self.policy_file = os.path.join(self.tmp, "policy.json")
        with open(self.policy_file, "w") as f:
            json.dump(pol, f)
        os.environ[f"{M.APP_ENV}_POLICY"] = self.policy_file
        M._P = None

    def policy_extra(self) -> dict:
        return {}

    def tearDown(self):
        if HAVE_TMUX:
            subprocess.run(["tmux", "-L", self.socket, "kill-server"], stderr=subprocess.DEVNULL)
        shutil.rmtree(self.tmp, ignore_errors=True)
        M._P = None

    def call(self, tool, /, **args):
        r = M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
        res = r["result"]
        return res["content"][0]["text"], bool(res.get("isError"))

    def ok(self, tool, /, **args):
        text, err = self.call(tool, **args)
        self.assertFalse(err, text)
        return text

    def refused(self, tool, /, **args):
        text, err = self.call(tool, **args)
        self.assertTrue(err, text)
        self.assertTrue(text.startswith("refused:"), text)
        return text

    def profile(self):
        with open(self.prof) as f:
            return f.read()

    def audit_ends(self):
        with open(os.path.join(self.tmp, "state", "audit.jsonl")) as f:
            return [json.loads(x) for x in f.read().splitlines() if '"phase": "end"' in x]

    def set_policy(self, **changes):
        with open(self.policy_file) as f:
            pol = json.load(f)
        pol.update(changes)
        with open(self.policy_file, "w") as f:
            json.dump(pol, f)
        M._P = None


class Protocol(Base):
    def test_handshake_and_tools(self):
        r = M.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(r["result"]["serverInfo"]["name"], "mac-terminal")
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        names = [t["name"] for t in M.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        self.assertEqual(sorted(names), sorted(["run", "session_start", "session_send", "session_read", "session_list",
                                                "session_stop", "read_file", "write_file", "edit_file", "open",
                                                "notify", "keep_awake", "status"]))
        # 0.4.0: no remote-host tools; nothing here reaches a host
        self.assertFalse([n for n in names if n.startswith("hosts_")], names)
        for t in M.tools():
            self.assertFalse(t["inputSchema"]["additionalProperties"], t["name"])
            self.assertIn("annotations", t)
            # 0.7.1: a title on every tool, in both places clients look; and a read-only or destructive hint
            self.assertTrue(t["title"], t["name"])
            self.assertEqual(t["annotations"]["title"], t["title"], t["name"])
            ann = t["annotations"]
            self.assertTrue("readOnlyHint" in ann or "destructiveHint" in ann, t["name"])

    def test_every_argument_and_tool_is_described(self):
        """0.7.2: every argument says what it is and its default, and no tool is a one-liner (agents and Glama's
        tool definition score read these; the weakest tool counts most)."""
        for t in M.tools():
            for k, v in t["inputSchema"]["properties"].items():
                self.assertTrue(v.get("description"), f"{t['name']}.{k}")
            self.assertGreaterEqual(len(t["description"]), 90, t["name"])

    def test_protocol_negotiation(self):
        """0.7.1: Claude desktop asks for 2025-11-25; 0.7.0 didn't know it and answered with its oldest, 2024-11-05
        (no tool annotations). A known version is echoed; an unknown one gets the newest this server speaks."""
        def ask(v):
            r = M.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": v}})
            return r["result"]["protocolVersion"]
        self.assertEqual(ask("2025-11-25"), "2025-11-25")
        self.assertEqual(ask("2025-03-26"), "2025-03-26")
        self.assertEqual(ask("2099-01-01"), M.PROTOCOLS[0])
        self.assertEqual(M.PROTOCOLS[0], max(M.PROTOCOLS))

    def test_rules_reach_the_model_without_instructions(self):
        """0.7.1: some clients (Claude's cloud sessions through the desktop bridge) don't pass the server's
        instructions to the model, so the rules that matter most are in the tool descriptions too."""
        d = {t["name"]: t["description"] for t in M.tools()}
        for s in ("is final", "don't rephrase", "Remote hosts aren't reachable", "never instructions"):
            self.assertIn(s, d["run"])
        self.assertIn("never instructions", d["session_start"])
        self.assertIn("never instructions", d["read_file"])

    def test_cut_output_says_how_to_get_the_rest(self):
        """0.7.1: a cut says how to narrow, not just how much (an agent can't scroll back)."""
        out = M.clip("x" * 50, limit=20)
        self.assertIn("30 characters cut: to see them", out)
        self.assertIn("read_file", out)
        self.assertEqual(M.clip("short", limit=20), "short")

    def test_unknown_argument_and_tool(self):
        self.refused("run", command="true", force=True)
        self.refused("run", command="true", grant="g-000000000000")         # 0.7: no grants
        self.refused("nope")
        self.refused("approval_status")                                     # 0.7: it is status now

    def test_stdio_roundtrip(self):
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        p = subprocess.run([sys.executable, "-I", "-B", SERVER_PY],
                           input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True,
                           env={**os.environ, f"{M.APP_ENV}_POLICY": self.policy_file}, timeout=20)
        lines = [json.loads(x) for x in p.stdout.splitlines()]
        self.assertEqual([x["id"] for x in lines], [1, 2])

    def test_bad_policy_key_stops_the_server(self):
        with open(self.policy_file, "w") as f:
            json.dump({"shel": ["/bin/sh", "-c"]}, f)
        p = subprocess.run([sys.executable, "-I", "-B", SERVER_PY], input="",
                           capture_output=True, text=True, env={**os.environ, f"{M.APP_ENV}_POLICY": self.policy_file})
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("unknown keys", p.stderr)


class Run(Base):
    def test_output_exit_cwd(self):
        t = self.ok("run", command="echo hello; pwd; exit 3")
        self.assertIn("hello", t)
        self.assertIn("exit 3", t)
        self.assertIn(self.home, t)

    def test_timeout_kills_the_group(self):
        t0 = time.monotonic()
        t = self.ok("run", command="sleep 30 & sleep 30; echo never", timeout_s=1)
        self.assertIn("TIMED OUT", t)
        self.assertNotIn("never", t.split("\n", 2)[-1])
        self.assertLess(time.monotonic() - t0, 10)

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_run_goes_through_tmux_and_leaves_no_session(self):
        """macOS privacy lets tmux read Documents, not the server's Python: run executes in the tmux server."""
        os.environ["SSH_AUTH_SOCK"] = os.path.join(self.tmp, "agent.sock")
        self.addCleanup(os.environ.pop, "SSH_AUTH_SOCK", None)
        t = self.ok("run", command="echo in:${TMUX:+tmux}:${SSH_AUTH_SOCK:+agent}; echo to-stderr >&2; exit 4",
                    outside_sandbox=True, why="test: look at the pane's environment")
        self.assertIn("in:tmux:agent", t)
        f = self.ok("run", command="echo fenced:${TMUX:-unset}:${TMUX_PANE:-unset}:${SSH_AUTH_SOCK:-unset}")
        self.assertIn("fenced:unset:unset:unset", f)                    # v0.7: they point at unsandboxed servers
        self.assertIn("to-stderr", t)
        self.assertIn("exit 4", t)
        self.assertNotIn(M.X_PREFIX, self.ok("session_list"))
        r = subprocess.run(["tmux", "-L", self.socket, "list-sessions", "-F", "#{session_name}"], capture_output=True,
                           text=True)
        self.assertNotIn(M.X_PREFIX, r.stdout)
        self.assertEqual(os.listdir(os.path.join(self.tmp, "state", "x")), [])

    def test_timeout_capped_by_policy(self):
        self.refused("run", command="true", timeout_s=46)

    def test_deny_list(self):
        for cmd in ("sudo ls", "/usr/bin/sudo -n true", "ssh prod-host", "scp a b:", "ansible-playbook x.yml",
                    "bash -c 'security find-generic-password -s some-mcp-token -w'", "security dump-keychain",
                    "cat ~/.ssh/id_ed25519",
                    f"ls {os.path.join(self.tmp, 'state')}"):
            self.assertIn("deny", self.refused("run", command=cmd), cmd)

    def test_cwd_in_a_denied_path(self):
        os.makedirs(os.path.join(self.tmp, "secret"))
        self.refused("run", command="ls", cwd=os.path.join(self.tmp, "secret"))

    def test_deny_list_no_false_positives(self):
        for cmd in ("echo pseudo sudoku", "echo ssh-keygen openssh", "echo security review", "echo summary"):
            self.ok("run", command=cmd)


class Audit(Base):
    def test_every_call_is_logged_and_secrets_are_not(self):
        self.ok("run", command="export TOKEN=abc123supersecret; echo password=hunter2 >/dev/null")
        self.refused("run", command="sudo true")
        f = os.path.join(self.home, "f.txt")
        self.ok("write_file", path=f, content="api_key=zzz-should-not-be-logged")
        with open(os.path.join(self.tmp, "state", "audit.jsonl")) as f:
            log = f.read()
        for secret in ("abc123supersecret", "hunter2", "zzz-should-not-be-logged"):
            self.assertNotIn(secret, log)
        recs = [r for r in (json.loads(x) for x in log.splitlines()) if r["phase"] != "selftest"]
        self.assertEqual([r["phase"] for r in recs], ["start", "end"] * 3)
        self.assertTrue(recs[3]["result"].startswith("refused"))
        self.assertEqual(oct(os.stat(os.path.join(self.tmp, "state", "audit.jsonl")).st_mode & 0o777), "0o600")


class Files(Base):
    def test_write_read_modes(self):
        f = os.path.join(self.home, "a", "b.txt")
        self.refused("write_file", path=f, content="x")                    # no parent
        self.ok("write_file", path=f, content="one\ntwo\n", make_dirs=True)
        self.refused("write_file", path=f, content="again")                # create refuses an existing file
        os.chmod(f, 0o600)
        self.ok("write_file", path=f, content="1\n2\n3\n", mode="overwrite")
        self.assertEqual(os.stat(f).st_mode & 0o777, 0o600)                # permissions kept
        self.ok("write_file", path=f, content="4\n", mode="append")
        t = self.ok("read_file", path="a/b.txt", offset=2, limit=2)        # relative to default_cwd
        self.assertIn("     2\t2", t)
        self.assertIn("     3\t3", t)
        self.assertNotIn("\t4", t)

    def test_denied_and_binary(self):
        os.makedirs(os.path.join(self.tmp, "secret"))
        s = os.path.join(self.tmp, "secret", "k")
        with open(s, "w") as f:
            f.write("x")
        self.refused("read_file", path=s)
        self.refused("write_file", path=os.path.join(self.tmp, "state", "checks.json"), content="{}", mode="overwrite")
        link = os.path.join(self.home, "innocent")
        os.symlink(s, link)
        self.refused("read_file", path=link)                               # symlinks resolve before the check
        b = os.path.join(self.home, "b.bin")
        with open(b, "wb") as f:
            f.write(b"\x00\x01")
        self.refused("read_file", path=b)


class Edit(Base):
    def setUp(self):
        super().setUp()
        self.f = os.path.join(self.home, "e.py")
        with open(self.f, "w") as f:
            f.write("def a():\n    return 1\n\n\ndef b():\n    return 1\n")
        os.chmod(self.f, 0o640)

    def text(self):
        with open(self.f, newline="") as f:
            return f.read()

    def test_exact_unique_and_replace_all(self):
        t = self.ok("edit_file", path=self.f, old_string="def a():\n    return 1", new_string="def a():\n    return 2")
        self.assertIn("1 replacement at line 1", t)
        self.assertIn("     2\t    return 2", t)                   # shows the result, numbered
        self.assertEqual(self.text(), "def a():\n    return 2\n\n\ndef b():\n    return 1\n")
        self.assertEqual(os.stat(self.f).st_mode & 0o777, 0o640)        # permissions kept
        with open(self.f, "a") as f:
            f.write("def c():\n    return 1\n")
        self.assertIn("(lines 6, 8)", self.refused("edit_file", path=self.f, old_string="return 1",
                                                                  new_string="return 3"))
        self.ok("edit_file", path=self.f, old_string="return 1", new_string="return 3", replace_all=True)
        self.assertEqual(self.text().count("return 3"), 2)

    def test_near_miss_says_where_and_how_and_changes_nothing(self):
        before = self.text()
        t = self.refused("edit_file", path=self.f, old_string="def b():\n  return 1", new_string="def b():\n  return 9")
        self.assertIn("Closest: line 5", t)
        self.assertIn("only whitespace", t)
        self.assertIn("{-", t)
        self.assertIn("never applied", t)
        t = self.refused("edit_file", path=self.f, old_string="def b():\n    retrun 1", new_string="x")
        self.assertIn("line 5", t)
        self.assertIn("ret{-ru-}{+ur+}n 1", t)
        self.assertIn("not in", self.refused("edit_file", path=self.f, old_string="zzzz qqqq wwww", new_string="x"))
        self.assertEqual(self.text(), before)

    def test_line_ends_encodings_and_nonsense(self):
        with open(self.f, "wb") as f:
            f.write(b"one\r\ntwo\r\nthree\r\n")
        self.ok("edit_file", path=self.f, old_string="two\nthree", new_string="2\n3")
        self.assertEqual(self.text(), "one\r\n2\r\n3\r\n")               # Windows line ends kept
        with open(self.f, "wb") as f:
            f.write(b"caf\xe9\n")
        self.assertIn("not UTF-8", self.refused("edit_file", path=self.f, old_string="caf", new_string="x"))
        self.refused("edit_file", path=self.f, old_string="", new_string="x")
        self.refused("edit_file", path=self.f, old_string="a", new_string="a")
        self.refused("edit_file", path=os.path.join(self.home, "missing.txt"), old_string="a", new_string="b")
        self.refused("edit_file", path=os.path.join(self.tmp, "state", "audit.jsonl"), old_string="a", new_string="b")

    def test_strings_are_not_in_the_audit_log(self):
        self.ok("edit_file", path=self.f, old_string="return 1\n\n\n", new_string="return 'hunter2-secret'\n\n\n")
        with open(os.path.join(self.tmp, "state", "audit.jsonl")) as f:
            log = f.read()
        self.assertNotIn("hunter2", log)
        self.assertIn('"sha256"', log)

    def test_does_not_write_over_a_change_made_meanwhile(self):
        real, n = M.read_bytes, [0]

        def read_then_someone_edits(path, *a, **k):
            data = real(path, *a, **k)
            n[0] += 1
            if n[0] == 1:
                with open(self.f, "a") as fh:
                    fh.write("his own edit\n")
            return data
        M.read_bytes = read_then_someone_edits
        try:
            self.assertIn("changed while", self.refused("edit_file", path=self.f, old_string="def a():",
                                                        new_string="def z():"))
        finally:
            M.read_bytes = real
        self.assertTrue(self.text().startswith("def a():"))
        self.assertTrue(self.text().endswith("his own edit\n"))


def _zip(path, files):
    import zipfile
    with zipfile.ZipFile(path, "w") as z:
        for name, body in files.items():
            z.writestr(name, body)


W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
S = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
REL = 'xmlns="http://schemas.openxmlformats.org/package/2006/relationships"'
A = 'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
PP = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'


def tiny_pdf(text: str) -> bytes:
    stream = f"BT /F1 18 Tf 20 100 Td ({text}) Tj ET"
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 144] /Contents 4 0 R "
            "/Resources << /Font << /F1 5 0 R >> >> >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode()
    x = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{o:010d} 00000 n \n".encode() for o in offs)
    return out + f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()


class Office(Base):
    def test_docx(self):
        p = os.path.join(self.home, "memo.docx")
        _zip(p, {"word/document.xml": f'<w:document {W}><w:body>'
                 '<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Plan</w:t></w:r></w:p>'
                 '<w:p><w:r><w:t xml:space="preserve">Ship </w:t></w:r><w:r><w:t>v0.3.2</w:t></w:r></w:p>'
                 '<w:tbl><w:tr><w:tc><w:p><w:r><w:t>who</w:t></w:r></w:p></w:tc>'
                 '<w:tc><w:p><w:r><w:t>Alice</w:t></w:r></w:p></w:tc></w:tr></w:tbl>'
                 '</w:body></w:document>'})
        t = self.ok("read_file", path=p)
        self.assertIn("# Plan", t)
        self.assertIn("Ship v0.3.2", t)
        self.assertIn("| who | Alice |", t)

    def test_xlsx(self):
        p = os.path.join(self.home, "budget.xlsx")
        _zip(p, {"xl/workbook.xml": f'<workbook {S} {R}><sheets><sheet name="Q4" sheetId="1" r:id="rId1"/></sheets></workbook>',
                 "xl/_rels/workbook.xml.rels": f'<Relationships {REL}><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>',
                 "xl/sharedStrings.xml": f'<sst {S}><si><t>item</t></si><si><t>cost</t></si><si><t>VPS</t></si></sst>',
                 "xl/worksheets/sheet1.xml": f'<worksheet {S}><sheetData>'
                 '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row>'
                 '<row r="2"><c r="A2" t="s"><v>2</v></c><c r="C2"><f>B2*2</f><v>84</v></c></row>'
                 '<row r="3"><c r="B3"><f>SUM(B1:B2)</f></c></row>'
                 '</sheetData></worksheet>'})
        t = self.ok("read_file", path=p)
        self.assertIn("## Sheet: Q4", t)
        self.assertIn("1\titem\tcost", t)
        self.assertIn("2\tVPS\t\t84", t)
        self.assertIn("3\t\t=SUM(B1:B2)", t)

    def test_pptx(self):
        p = os.path.join(self.home, "deck.pptx")
        _zip(p, {"ppt/presentation.xml": f'<p:presentation {PP} {R}><p:sldIdLst><p:sldId id="257" r:id="rId3"/>'
                 '<p:sldId id="256" r:id="rId2"/></p:sldIdLst></p:presentation>',
                 "ppt/_rels/presentation.xml.rels": f'<Relationships {REL}><Relationship Id="rId2" Target="slides/slide1.xml"/>'
                 '<Relationship Id="rId3" Target="slides/slide2.xml"/></Relationships>',
                 "ppt/slides/slide1.xml": f'<p:sld {PP} {A}><a:p><a:r><a:t>second</a:t></a:r></a:p></p:sld>',
                 "ppt/slides/slide2.xml": f'<p:sld {PP} {A}><a:p><a:r><a:t>first</a:t></a:r></a:p></p:sld>'})
        t = self.ok("read_file", path=p)
        self.assertLess(t.index("first"), t.index("second"))            # presentation order, not file names
        self.assertIn("## Slide 2", t)

    def test_hostile_and_broken_files(self):
        p = os.path.join(self.home, "bomb.docx")
        _zip(p, {"word/document.xml": f'<!DOCTYPE x [<!ENTITY a "aaaa">]><w:document {W}><w:body/></w:document>'})
        self.assertIn("DTD", self.refused("read_file", path=p))
        p = os.path.join(self.home, "fake.xlsx")
        with open(p, "w") as f:
            f.write("not a zip")
        self.assertIn("not a zip", self.refused("read_file", path=p))

    def test_pdf(self):
        p = os.path.join(self.home, "r.pdf")
        with open(p, "wb") as f:
            f.write(tiny_pdf("Hello from mac-terminal"))
        if not ON_MAC or not shutil.which("swiftc"):
            self.assertIn("PDFKit", self.refused("read_file", path=p))
            return
        t, err = self.call("read_file", path=p)
        for _ in range(8):                                              # the first read builds the reader once
            if not (err and "being built" in t):
                break
            time.sleep(10)
            t, err = self.call("read_file", path=p)
        self.assertFalse(err, t)
        self.assertIn("## Page 1", t)
        self.assertIn("Hello from mac-terminal", t)


@unittest.skipUnless(HAVE_TMUX, "needs tmux")
class Sessions(Base):
    def test_job_session(self):
        t = self.ok("session_start", name="job1", command="echo one; sleep 1; echo two; exit 3", wait_s=15)
        self.assertIn("two", t)
        self.assertIn("[mac-terminal: exit 3]", t)
        self.assertIn("job exited 3", t)
        self.assertIn("job1", self.ok("session_list"))
        self.assertIn("job exited 3", self.ok("session_read", name="job1", wait_s=10))   # no wait for a finished job
        self.refused("session_start", name="job1")                        # names are unique
        self.ok("session_stop", name="job1")
        self.assertEqual(self.ok("session_list"), "no sessions")

    def test_long_job_then_read_until_finished(self):
        t = self.ok("session_start", name="slow", command="sleep 3; echo late", wait_s=0.5)
        self.assertIn("job running", t)
        t = self.ok("session_read", name="slow", wait_s=15)
        self.assertIn("late", t)
        self.assertIn("job finished", t)

    def test_interactive_session(self):
        self.ok("session_start", name="sh")
        t = self.ok("session_send", name="sh", text="echo hi-$((40+2))", wait_s=5)
        self.assertIn("hi-42", t)
        t = self.ok("session_send", name="sh", text="sleep 1; echo DONE-X", until="^DONE-X$", wait_s=10)
        self.assertIn("until matched", t)
        self.ok("session_send", name="sh", text="sleep 30", wait_s=0.5)
        t = self.ok("session_send", name="sh", key="C-c", wait_s=3)
        self.assertIn("foreground: bash", t)
        self.refused("session_send", name="sh", text="sudo -v")
        self.refused("session_send", name="sh", key="C-x")
        self.refused("session_send", name="nosuch", text="ls")
        self.refused("session_start", name="bad name!")

    def test_parallel_sessions(self):
        for i in range(3):
            self.ok("session_start", name=f"p{i}", command=f"sleep 2; echo P{i}", wait_s=0)
        for i in range(3):
            self.assertIn(f"P{i}", self.ok("session_read", name=f"p{i}", wait_s=15))


class NoRemoteHosts(Base):
    def test_remote_hosts_are_refused_here(self):
        """0.4.0: ssh, scp and ansible stay denied; this server reaches no remote host."""
        for cmd in ("ssh h true", "scp a h:/tmp/", "ansible-playbook x.yml"):
            self.assertIn("deny", self.refused("run", command=cmd).lower())
        self.assertEqual(M.load_policy(None)["protected_folders"], [])


@unittest.skipUnless(ON_MAC, "macOS only")
class MacOnly(Base):
    def test_keep_awake_cycle(self):
        self.ok("keep_awake", mode="on", hours=0.01)
        self.assertIn("keeping the Mac awake", self.ok("keep_awake", mode="status"))
        self.assertIn("released", self.ok("keep_awake", mode="off"))
        self.assertIn("not keeping", self.ok("keep_awake", mode="status"))

    def test_open_refusals(self):
        self.refused("open", target="file:///etc/passwd")
        self.refused("open", target="~/.ssh")
        self.refused("open", app="Bad;App")


@unittest.skipUnless(HAVE_TMUX, "needs tmux")
class PrivacyFallback(Base):
    def test_files_go_through_tmux_when_this_process_may_not(self):
        """Like macOS privacy for the server's Python in Documents: read_file and write_file still work."""
        import builtins
        prot = os.path.join(self.home, "Documents")
        os.makedirs(prot)
        with open(os.path.join(prot, "r.txt"), "w") as f:
            f.write("one\ntwo\n")
        real_open, real_mkstemp = builtins.open, tempfile.mkstemp

        def inside(path):
            try:
                return os.path.realpath(os.fspath(path)).startswith(prot)
            except TypeError:
                return False

        def open_(path, *a, **k):
            if inside(path):
                raise PermissionError(1, "Operation not permitted", path)
            return real_open(path, *a, **k)

        def mkstemp_(*a, **k):
            if inside(k.get("dir") or ""):
                raise PermissionError(1, "Operation not permitted")
            return real_mkstemp(*a, **k)
        builtins.open, tempfile.mkstemp = open_, mkstemp_
        try:
            self.assertIn("     2\ttwo", self.ok("read_file", path=os.path.join(prot, "r.txt")))
            self.ok("write_file", path=os.path.join(prot, "w.txt"), content="written\n")
            self.ok("write_file", path=os.path.join(prot, "w.txt"), content="more\n", mode="append")
            self.ok("edit_file", path=os.path.join(prot, "w.txt"), old_string="more", new_string="edited")
        finally:
            builtins.open, tempfile.mkstemp = real_open, real_mkstemp
        with open(os.path.join(prot, "w.txt")) as f:
            self.assertEqual(f.read(), "written\nedited\n")


# ----------------------------------------------------------------------------------------------- v0.7: no dialogs --
class Name(Base):
    """0.7: renamed from Mac Ops (mac-ops, MAC_OPS, tmux socket "claude")."""

    def test_the_name_lives_in_constants(self):
        self.assertEqual((M.APP, M.APP_TITLE, M.APP_ENV), ("mac-terminal", "Mac Terminal MCP", "MAC_TERMINAL"))
        self.assertEqual(M.SERVER["name"], "mac-terminal")
        P = M.load_policy(None)
        self.assertEqual(P["tmux_socket"], "mac-terminal")
        self.assertEqual(P["state_dir"], os.path.realpath(os.path.expanduser("~/.local/state/mac-terminal")))
        self.assertIn(P["state_dir"], P["deny_paths"])
        self.assertNotIn(os.path.realpath(os.path.expanduser("~/.local/state/mac-ops")), P["deny_paths"])
        self.assertTrue(M.MARKER_RE.search("[mac-terminal: exit 7]"))
        self.assertFalse(M.MARKER_RE.search("[mac-ops: exit 7]"))
        with open(os.path.join(ROOT, "mac_terminal_mcp.py"), encoding="utf-8") as f:
            code = f.read().split('"""', 2)[2]                          # below the module docstring
        self.assertEqual(code.count("mac-terminal"), 1, "the name is spelled out once: APP")
        self.assertEqual(code.count("Mac Terminal MCP"), 1, "and its title once: APP_TITLE")

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_commands_see_the_env_marker(self):
        self.assertIn("marker=1", self.ok("run", command="echo marker=${MAC_TERMINAL:-none}"))


class Installer(unittest.TestCase):
    """install.sh against a scratch HOME, Claude config and install folder: the upgrade from Mac Ops."""

    def setUp(self):
        self.t = tempfile.mkdtemp(prefix="mac-terminal-inst-")
        self.addCleanup(shutil.rmtree, self.t, True)
        self.home = os.path.join(self.t, "home")
        self.dest = os.path.join(self.home, ".config", "claude-mcp")
        self.cfg = os.path.join(self.t, "claude_desktop_config.json")
        old = os.path.join(self.dest, "mac-ops")
        os.makedirs(old)
        for name in ("mac_ops_server.py", "policy.json"):
            with open(os.path.join(old, name), "w") as f:
                f.write("old\n")
            os.chmod(os.path.join(old, name), 0o444)
        self.old_state = os.path.join(self.home, ".local", "state", "mac-ops")
        os.makedirs(self.old_state)
        with open(os.path.join(self.old_state, "audit.jsonl"), "w") as f:
            f.write("{}\n")
        with open(self.cfg, "w") as f:
            json.dump({"mcpServers": {"mac-ops": {"command": "/usr/bin/python3", "args": ["x"]},
                                      "other": {"command": "keep-me"}}}, f)
        self.env = {k: v for k, v in os.environ.items() if k not in ("MAC_TERMINAL", "MAC_OPS")}
        self.env.update(HOME=self.home, MCP_DEST=self.dest, CLAUDE_CONFIG=self.cfg, SKIP_APP_CONTROL="1",
                        TMPDIR=os.environ.get("TMPDIR", "/tmp"))

    def sh(self, *args, env=None):
        return subprocess.run(["/bin/bash", os.path.join(ROOT, "install.sh"), *args], capture_output=True, text=True,
                              env=env or self.env, timeout=170)

    def servers(self):
        with open(self.cfg) as f:
            return json.load(f)["mcpServers"]

    @unittest.skipUnless(os.access("/usr/bin/python3", os.X_OK), "install.sh needs /usr/bin/python3")
    def test_upgrade_from_mac_ops(self):
        r = self.sh("--check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('Old Mac Ops entry "mac-ops" in the Claude config', r.stdout)
        self.assertIn("Old Mac Ops copy at", r.stdout)
        self.assertIn(f"Old Mac Ops state (audit log): {self.old_state}", r.stdout)
        self.assertEqual(sorted(self.servers()), ["mac-ops", "other"])         # --check changes nothing
        self.assertTrue(os.path.isdir(os.path.join(self.dest, "mac-ops")))
        r = self.sh("--skip-tests")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        s = self.servers()
        self.assertEqual(sorted(s), ["mac-terminal", "other"])
        self.assertEqual(s["other"], {"command": "keep-me"})
        inst = os.path.join(self.dest, "mac-terminal")
        self.assertEqual(s["mac-terminal"]["args"], ["-I", "-B", f"{inst}/mac_terminal_mcp.py"])
        self.assertEqual(s["mac-terminal"]["env"], {"MAC_TERMINAL_POLICY": f"{inst}/policy.json"})
        self.assertIn("the old \"mac-ops\" entry is gone", out)
        self.assertFalse(os.path.exists(os.path.join(self.dest, "mac-ops")))
        self.assertIn("Removed the old Mac Ops copy", out)
        self.assertTrue(os.path.exists(os.path.join(self.old_state, "audit.jsonl")))     # the old log stays
        self.assertIn(f"Kept the old Mac Ops state folder, with its audit log: {self.old_state}", out)
        self.assertTrue(os.path.isfile(os.path.join(inst, "mac_terminal_mcp.py")))
        r = self.sh("--check")
        self.assertNotIn("Old Mac Ops entry", r.stdout)
        self.assertNotIn("Old Mac Ops copy", r.stdout)
        self.assertIn("mac-terminal entry present", r.stdout)
        r = self.sh("--remove")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(self.servers()), ["other"])
        self.assertFalse(os.path.exists(inst))

    def test_refuses_to_install_from_a_command_it_runs(self):
        for var in ("MAC_TERMINAL", "MAC_OPS"):
            r = self.sh(env=dict(self.env, **{var: "1"}))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("runs from your own Terminal", r.stderr)
        self.assertEqual(sorted(self.servers()), ["mac-ops", "other"])


class NoDialogs(Base):
    def test_no_dialog_or_grant_code_is_left(self):
        for name in ("show_dialog", "ask", "dialog_script", "tier1_dialog", "tier2_dialog", "grant_dialog",
                     "every_dialog", "preview_dialogs", "t_request_grant", "t_revoke_grant", "t_approval_status",
                     "gate", "classify", "is_read_only", "tier2_label", "programs_run", "GRANTS", "ALLOWED",
                     "approvals_mode"):
            self.assertFalse(hasattr(M, name), name)
        with open(SERVER_PY, encoding="utf-8") as f:
            src = f.read()
        for s in ("display alert", "display dialog", "choose from list", "--preview-dialogs"):
            self.assertNotIn(s, src)
        for t in M.tools():
            self.assertNotIn("grant", t["inputSchema"]["properties"], t["name"])
        for k in ("approvals", "confirm_tools", "confirm_with", "always_ask", "grant_minutes"):
            self.assertNotIn(k, M.load_policy(None))

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_no_call_starts_osascript(self):
        """0.6 asked in a macOS alert (osascript) before a write, a non-read command or a session. Nothing does now."""
        seen, real = [], subprocess.Popen

        class Recording(real):
            def __init__(self, argv, *a, **k):
                seen.append(argv if isinstance(argv, str) else " ".join(map(str, argv)))
                super().__init__(argv, *a, **k)
        subprocess.Popen = Recording
        try:
            f = os.path.join(self.home, "n.txt")
            self.ok("run", command="touch made && echo hi")
            self.ok("write_file", path=f, content="one\n")
            self.ok("edit_file", path=f, old_string="one", new_string="two")
            self.ok("session_start", name="nd", command="echo job")
            self.ok("session_send", name="nd", text="touch typed", wait_s=1)
            self.ok("status")
        finally:
            subprocess.Popen = real
        self.assertTrue(seen)
        self.assertFalse([x for x in seen if "osascript" in x], seen)
        self.assertTrue(os.path.exists(os.path.join(self.home, "made")))


class Fence(Base):
    def test_one_profile_with_the_protections(self):
        self.assertIn("fenced: macOS sandbox", self.ok("run", command="true"))
        p = self.profile()
        P = M.policy()
        h = os.path.realpath(os.path.expanduser("~"))
        self.assertTrue(p.startswith("(version 1)\n(allow default)\n"), p)
        self.assertNotIn("(deny network*)", p)                              # network on by default
        allow = [ln for ln in p.splitlines() if ln.startswith("(deny file-write* (require-not")]
        self.assertEqual(len(allow), 1, p)                                  # no blanket write deny: home is writable
        self.assertTrue(allow[0].startswith(f'(deny file-write* (require-not (require-any (subpath "{h}")'), allow)
        for t in M.temp_dirs():
            self.assertIn(f'(subpath "{t}")', allow[0])
        deny = [ln for ln in p.splitlines() if ln.startswith("(deny file-write* (") and ln not in allow]
        self.assertEqual(len(deny), 1, p)
        for d in (P["protected_paths"] + [os.path.realpath(self.protected), P["state_dir"]] + P["deny_paths"] +
                  M.tmux_paths()):
            self.assertIn(f'(subpath "{d}")', deny[0], d)
            self.assertIn(M.ci_path_rx(d), deny[0], d)                      # and in any letter case
        for rx in P["protected_writes"]:
            self.assertIn(f'(regex #"{M.ci_rx(rx)}")', deny[0], rx)
        st = os.path.realpath(os.path.join(self.tmp, "state"))
        reads = [ln for ln in p.splitlines() if ln.startswith("(deny file-read* ")]
        self.assertEqual(len(reads), 1, p)
        self.assertIn(f'(subpath "{os.path.realpath(os.path.join(self.tmp, "secret"))}")', reads[0])
        self.assertNotIn(st, reads[0])
        self.assertIn(f'(deny file-read-data (subpath "{st}") (regex #"{M.ci_path_rx(st)}(/|$)"))', p)
        self.assertNotIn(f'(deny file-read* (subpath "{st}")', p)          # programs fstat() their output in there
        self.assertIn('(literal "/usr/bin/osascript")', p)
        for rule in M.SB_EXTRAS.values():
            self.assertIn(rule, p)

    def test_default_protections(self):
        P = M.load_policy(None)
        for x in ("~/.zshrc", "~/.zprofile", "~/.bashrc", "~/.gitconfig", "~/Library/LaunchAgents", "~/Applications",
                  "~/.local/bin", "~/.oh-my-zsh", "~/.config/zsh", "~/.npmrc", "~/.docker/cli-plugins"):
            self.assertIn(os.path.realpath(os.path.expanduser(x)), P["protected_paths"], x)
        self.assertIn(os.path.realpath(os.path.expanduser("~/.config/gh")), P["deny_paths"])
        self.assertEqual(P["fence_writable"], [os.path.realpath(os.path.expanduser("~"))])
        for path in ("/p/.git/hooks/pre-commit", "/p/.git/config", "/p/.git", "/p/.vscode/tasks.json", "/p/.mcp.json",
                     "/p/.claude/settings.json", "/p/.claude/settings.local.json", "/p/.claude/hooks/x.sh",
                     "/p/.claude/agents/a.md", "/h/.claude.json", "/p/.envrc", "/p/.gitmodules", "/p/.idea/x.xml"):
            self.assertTrue(any(rx.search(path) for rx in P["_protected_writes"]), path)
        for path in ("/p/.git/objects/ab/cd", "/p/.git/info/exclude", "/p/.gitignore", "/p/src/app.py",
                     "/p/.claude/notes.md"):
            self.assertFalse(any(rx.search(path) for rx in P["_protected_writes"]), path)
        self.assertTrue(P["network"])
        self.assertTrue(P["allow_outside_sandbox"])
        self.assertEqual(P["sandbox_fail"], "refuse")
        self.assertEqual(M.ci_rx("/[.]git$"), "/[.][gG][iI][tT]$")
        self.assertEqual(M.ci_path_rx("/a.b/C"), "^/[aA][.][bB]/[cC]")
        self.assertIsNone(M.ci_path_rx('/x"y'))

    def test_fence_writable_is_the_policy(self):
        self.set_policy(fence_writable=[self.home])
        self.ok("run", command="true")
        self.assertIn(f'(require-any (subpath "{os.path.realpath(self.home)}")', self.profile())

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_sessions_keep_their_sandbox(self):
        t = self.ok("session_start", name="f1")
        self.assertIn("session f1 (fenced)", t)
        self.assertIn("fenced: macOS sandbox", t)
        self.assertIn("fake-sandbox-exec", M.tmux("list-panes", "-t", "=f1:", "-F", "#{pane_start_command}"))
        self.ok("session_send", name="f1", text="echo typed", wait_s=2)
        self.assertEqual(self.audit_ends()[-1]["how"], "fenced")


    def test_selftest_stand_ins_reach_the_profile(self):
        p = M.sb_profile(extras=[], roots=["/x/work"], more_deny=["/x/work/denied"], more_protected=["/x/work/rc"])
        lines = p.splitlines()
        h = os.path.realpath(os.path.expanduser("~"))
        self.assertTrue(lines[2].startswith('(deny file-write* (require-not (require-any (subpath "/x/work")'), lines[2])
        self.assertNotIn(f'(subpath "{h}")', lines[2])                   # the real home is not a root then
        self.assertIn('(subpath "/x/work/rc")', lines[3])
        self.assertIn('(subpath "/x/work/denied")', lines[3])
        self.assertIn('(subpath "/x/work/denied")', [ln for ln in lines if ln.startswith("(deny file-read* ")][0])
        self.assertIn("(deny network*)", M.sb_profile(extras=[], network=False))


@unittest.skipUnless(HAVE_TMUX, "needs tmux")
class SelfTestHasTeeth(Base):
    """The stand-in sandbox-exec sandboxes nothing: the self-test must say so, never pass on missing evidence."""

    def policy_extra(self):
        return {"sandbox_selftest": True}

    def test_a_sandbox_that_does_not_sandbox_fails_the_self_test(self):
        st = M._selftest()
        self.assertFalse(st["ok"])
        self.assertIn("did not refuse writes outside its folders", st["reason"])
        self.assertEqual(st["checks"], ["shell starts, output comes back", "its folders and temp writable"])
        self.assertFalse([x for x in os.listdir(self.tmp) if "selftest" in x])           # its scratch is gone
        self.assertEqual(os.listdir(os.path.join(self.tmp, "state", "selftest")), [])
        self.assertIn("isn't working", self.refused("run", command="true"))               # sandbox_fail: refuse
        # It failed at the 'outside' write, whose profile leaves temp out: this run's scratch sits in temp here, as it
        # did on a Mac, where the probe could write 'outside' and the self-test failed on a sound sandbox (0.7.0).
        allow = [ln for ln in self.profile().splitlines() if "require-not" in ln][0]
        for t in M.temp_dirs():
            self.assertNotIn(f"(subpath {M.sbq(t)})", allow)
        self.assertIn("-selftest-", allow)

    def test_the_outside_probe_has_no_temp(self):
        work = os.path.join(self.tmp, "w")
        with_temp, bare = (M.sb_profile(extras=[], roots=[work], sockets=False, path_dirs=[], temp=t) for t in (True, False))
        for t in M.temp_dirs():
            self.assertIn(f"(subpath {M.sbq(t)})", with_temp)
            self.assertNotIn(f"(subpath {M.sbq(t)})", bare)
        self.assertIn(f"(subpath {M.sbq(work)})", bare)


class Sockets(Base):
    """v0.7: tmux (unsandboxed) runs whatever a connected client asks: the fence can't connect to it, nor to agents."""

    def test_unix_socket_rules_in_the_profile(self):
        os.environ["SSH_AUTH_SOCK"] = "/private/tmp/com.apple.launchd.AbC/Listeners"
        self.addCleanup(os.environ.pop, "SSH_AUTH_SOCK", None)
        self.ok("run", command="true")
        p = self.profile()
        uid = os.getuid()
        dirs = M.tmux_socket_dirs()
        self.assertTrue({f"/tmp/tmux-{uid}", f"/private/tmp/tmux-{uid}"} <= set(dirs), dirs)
        deny = [ln for ln in p.splitlines() if ln.startswith("(deny file-write* (subpath")][0]
        for d in dirs:
            rx = M.ci_path_rx(d)
            self.assertIn(f'(deny network-outbound (remote unix-socket (path-regex #"{rx}(/|$)")))', p)
            self.assertIn(f'(subpath "{d}")', deny)                         # and no writes there (rename, sockets)
        self.assertIn('(deny file-link (regex #"', p)
        for rx in ("/docker[.]sock$", "^/private/tmp/com[.]apple[.]launchd[.][^/]+/Listeners$", "/[.]colima/",
                   "/emacs[0-9]+/", "/vscode-ipc-[^/]+[.]sock$"):
            self.assertIn(f'(path-regex #"{M.ci_rx(rx)}")', p, rx)
        self.assertIn(M.ci_path_rx("/private/tmp/com.apple.launchd.AbC/Listeners") + "$", p)
        ssh = M.ci_path_rx(os.path.realpath(os.path.expanduser("~/.ssh")))
        self.assertIn(f'(remote unix-socket (path-regex #"{ssh}(/|$)"))', p)    # a denied path's sockets too
        reg = M.socket_rules("regex", False)
        self.assertTrue(reg and all(x.startswith('(deny network-outbound (regex #"') for x in reg), reg)
        lit = M.socket_rules("literal", True)
        self.assertIn(f'(deny network-outbound (literal "/private/tmp/tmux-{uid}/{self.socket}"))', lit)
        self.assertIn(f'(deny network-outbound (literal "/tmp/tmux-{uid}/default"))', lit)
        self.assertTrue(lit[-1].startswith("(deny file-link "), lit[-1])
        self.assertFalse([x for x in M.socket_rules("unix-socket", False) if "file-link" in x])

    def test_tmux_tmpdir_is_followed(self):
        os.environ["TMUX_TMPDIR"] = os.path.join(self.tmp, "tt")
        self.addCleanup(os.environ.pop, "TMUX_TMPDIR", None)
        self.assertIn(os.path.join(os.path.realpath(self.tmp), "tt", f"tmux-{os.getuid()}"), M.tmux_socket_dirs())

    def test_writes_into_tmux_folders_are_refused(self):
        for d in M.tmux_socket_dirs():
            self.assertIn("is protected", self.refused("write_file", path=os.path.join(d, "x"), content="x"))

    def test_path_folders_are_compared_as_real_paths(self):
        """On a Mac the temp folder is /var/folders/..., really /private/var/folders/...: a login-PATH folder spelled
        through a symlink must still protect the real folder, in write_file and in the profile (0.7.0 missed it)."""
        real = os.path.realpath(os.path.join(self.home, "bin"))
        os.makedirs(real)
        link = os.path.join(self.tmp, "home-link")
        os.symlink(self.home, link)
        self.ok("status")
        M.sandbox_status()["path_dirs"] = [os.path.join(link, "bin")]
        self.assertIn("login PATH", self.refused("write_file", path=os.path.join(real, "git"), content="x"))
        self.ok("run", command="true")
        self.assertIn(f"(subpath {M.sbq(real)})", self.profile())

    def test_path_folders_in_home_are_protected(self):
        h, t = M.home(), M.temp_dirs()[0]
        got = M.writable_path_dirs(f"/usr/bin:{h}/.cargo/bin:{h}:.:rel/bin:{h}/.cargo/bin:{t}/x/bin:/opt/homebrew/bin")
        self.assertEqual(got, [f"{h}/.cargo/bin", f"{t}/x/bin"])          # not a root itself, nor outside the roots
        self.ok("status")
        M.sandbox_status()["path_dirs"] = [os.path.join(self.home, "bin")]  # as the self-test finds them
        self.assertIn("login PATH", self.refused("write_file", path=os.path.join(self.home, "bin", "git"),
                                                 content="x", make_dirs=True))
        self.ok("run", command="true")
        self.assertIn(f'(subpath "{os.path.realpath(os.path.join(self.home, "bin"))}")', self.profile())

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_the_tmux_probe_sees_a_client_that_gets_through(self):
        """Unsandboxed, the probe reaches tmux: it must say so (its teeth), and read its markers right."""
        self.ok("run", command="true")                                      # this test's tmux server is up
        sock = M.via_tmux([M.tmux_exe(), "-L", self.socket, "list-sessions", "-F", "#{socket_path}"], self.home, 10,
                          merge=True)[1].strip().splitlines()[0]
        work = os.path.join(self.home, "w")
        os.makedirs(work)
        held, out = M.tmux_probe(lambda argv: M.via_tmux(argv, self.home, 15, merge=True)[:2], work, sock)
        self.assertFalse(held, out)
        self.assertIn("mac-terminal-tmux-reached-L", out)
        self.assertIn("mac-terminal-tmux-reached-sl", out)
        self.assertEqual(os.listdir(work), [])                              # its links are gone
        refused = "tmux-L-rc=1\ntmux-sl-rc=1\ntmux-hl-rc=1\n"
        self.assertTrue(M.tmux_probe(lambda argv: (0, refused), work, sock)[0])
        self.assertFalse(M.tmux_probe(lambda argv: (0, "tmux-L-rc=1\ntmux-sl-rc=1\n"), work, sock)[0])  # no evidence
        self.assertFalse(M.tmux_probe(lambda argv: (0, refused.replace("hl-rc=1", "hl-rc=0")), work, sock)[0])


class NetworkOff(Base):
    def policy_extra(self):
        return {"network": False}

    def test_network_rule_follows_the_policy(self):
        self.ok("run", command="true")
        self.assertIn("(deny network*)", self.profile())
        self.assertIn("network: off", self.ok("status"))


class OutsideSandbox(Base):
    def test_needs_a_why(self):
        for why in (None, "", "   "):
            args = {"command": "touch o1", "outside_sandbox": True}
            if why is not None:
                args["why"] = why
            self.assertIn("needs why", self.refused("run", **args))
        self.assertIn("needs why", self.refused("session_start", name="o", outside_sandbox=True))
        self.assertFalse(os.path.exists(os.path.join(self.home, "o1")))

    def test_runs_without_the_sandbox_and_says_so(self):
        t = self.ok("run", command="touch o1", outside_sandbox=True, why="the user asked for o1")
        self.assertIn("UNSANDBOXED (outside_sandbox: the user asked for o1)", t)
        self.assertTrue(os.path.exists(os.path.join(self.home, "o1")))
        self.assertFalse(os.path.exists(self.prof))                         # the stand-in sandbox-exec never ran
        end = self.audit_ends()[-1]
        self.assertEqual(end["how"], "unsandboxed")
        self.assertIn("the user asked for o1", end["why"])

    def test_fenced_by_default(self):
        self.ok("run", command="touch f1")
        self.assertTrue(os.path.exists(self.prof))
        self.assertEqual(self.audit_ends()[-1]["how"], "fenced")

    def test_deny_lists_still_apply(self):
        for cmd in ("sudo ls", "ssh h true", "cat ~/.ssh/id_ed25519", "security find-generic-password -w",
                    f"ls {os.path.join(self.tmp, 'state')}"):
            self.assertIn("deny", self.refused("run", command=cmd, outside_sandbox=True, why="the user asked"), cmd)
        self.refused("session_start", name="o", command="sudo -v", outside_sandbox=True, why="the user asked")
        self.assertEqual(self.audit_ends()[-1]["how"], "-")                 # refused before it was routed

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_an_unsandboxed_session_asks_for_the_flag_every_time(self):
        t = self.ok("session_start", name="u1", outside_sandbox=True, why="the user wants a plain shell")
        self.assertIn("session u1 (unsandboxed)", t)
        marker = os.path.join(self.home, "typed")
        for extra in ({}, {"outside_sandbox": True}, {"outside_sandbox": True, "why": "  "}, {"why": "the user asked"}):
            t = self.refused("session_send", name="u1", text=f"touch {marker}", **extra)
            self.assertIn("needs outside_sandbox=true and why", t, extra)
        self.refused("session_send", name="u1", key="C-c")                  # keys too
        time.sleep(1)
        self.assertFalse(os.path.exists(marker))
        self.ok("session_send", name="u1", text=f"touch {marker}", outside_sandbox=True,
                why="the user asked for the marker file", wait_s=3)
        for _ in range(20):
            if os.path.exists(marker):
                break
            time.sleep(0.2)
        self.assertTrue(os.path.exists(marker))
        end = self.audit_ends()[-1]
        self.assertEqual(end["how"], "unsandboxed")
        self.assertEqual(end["why"], "outside_sandbox: the user asked for the marker file")
        self.assertIn("u1 (unsandboxed)", self.ok("session_list"))
        self.assertIn("u1: unsandboxed", self.ok("status"))

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_a_fenced_session_refuses_the_flag(self):
        self.ok("session_start", name="f1")
        t = self.refused("session_send", name="f1", text="echo x", outside_sandbox=True, why="the user asked")
        self.assertIn("runs in the fence", t)
        self.ok("session_send", name="f1", text="echo x", wait_s=1)
        self.assertIn("f1 (fenced)", self.ok("session_list"))


class OutsideSandboxOff(Base):
    def policy_extra(self):
        return {"allow_outside_sandbox": False}

    def test_refused_when_the_policy_says_so(self):
        t = self.refused("run", command="touch o1", outside_sandbox=True, why="the user asked")
        self.assertIn("allow_outside_sandbox: false", t)
        self.refused("session_start", name="o", outside_sandbox=True, why="the user asked")
        self.assertFalse(os.path.exists(os.path.join(self.home, "o1")))
        self.assertIn("outside_sandbox: off", self.ok("status"))
        self.ok("run", command="echo fenced-still-works")

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_a_session_it_did_not_start_is_unsandboxed(self):
        M.policy()
        M.tmux("new-session", "-d", "-s", "manual")                     # e.g. the user's, on this server's socket
        t = self.refused("session_send", name="manual", text="echo x", outside_sandbox=True, why="the user asked")
        self.assertIn("runs outside the sandbox", t)
        self.assertIn("allow_outside_sandbox: false", t)


class ProtectedWrites(Base):
    """write_file and edit_file refuse what the fence protects, in the server's own Python (it isn't sandboxed)."""

    def policy_extra(self):
        self.rc = os.path.join(self.home, ".zshrc")
        self.la = os.path.join(self.home, "Library", "LaunchAgents")
        self.proj = os.path.join(self.home, "proj")
        return {"protected_paths": [self.rc, self.la]}

    def targets(self):
        p = self.proj
        return [self.rc, os.path.join(self.la, "x.plist"), os.path.join(p, ".git", "hooks", "pre-commit"),
                os.path.join(p, ".git", "config"), os.path.join(p, ".vscode", "tasks.json"),
                os.path.join(p, ".idea", "workspace.xml"), os.path.join(p, ".mcp.json"), os.path.join(p, ".envrc"),
                os.path.join(p, ".gitmodules"), os.path.join(p, ".claude", "commands", "x.md"),
                os.path.join(p, ".claude", "settings.json"), os.path.join(p, ".claude", "settings.local.json"),
                os.path.join(self.home, ".claude.json"), os.path.join(self.protected, "playbook.yml"),
                os.path.join(self.protected, "deep", "x.yml"), M.tmux_exe(),
                os.path.join("/usr/local", f"mac-terminal-test-{os.getpid()}")]

    def test_write_file_refuses_each_kind(self):
        for t in self.targets():
            msg = self.refused("write_file", path=t, content="x", mode="overwrite", make_dirs=True)
            self.assertIn("is protected", msg, t)
            if t != M.tmux_exe():
                self.assertFalse(os.path.exists(t), t)
        self.assertIn("a denied path", self.refused("write_file", path=os.path.join(self.tmp, "state", "x"),
                                                    content="x"))

    def test_edit_file_refuses_each_kind(self):
        for t in self.targets()[:-2]:                                       # all but tmux and /usr/local
            os.makedirs(os.path.dirname(t), exist_ok=True)
            with open(t, "w") as f:
                f.write("before\n")
            self.assertIn("is protected", self.refused("edit_file", path=t, old_string="before", new_string="after"))
            with open(t) as f:
                self.assertEqual(f.read(), "before\n", t)

    def test_other_letter_case(self):
        for t in (os.path.join(self.proj, ".GIT", "Hooks", "x"), os.path.join(self.proj, ".VSCode", "tasks.json"),
                  os.path.join(self.proj, ".Claude", "Settings.json")):
            self.assertIn("is protected", self.refused("write_file", path=t, content="x", make_dirs=True), t)
        if M.CASELESS:
            self.refused("write_file", path=self.rc.upper(), content="x", mode="overwrite")
            self.refused("read_file", path="~/.SSH/id_ed25519")
            self.assertIn("denied path", self.refused("run", command="cat ~/.SSH/id_ed25519"))

    def test_normal_files_are_written_without_asking(self):
        for t in (os.path.join(self.proj, "src", "app.py"), os.path.join(self.proj, ".gitignore"),
                  os.path.join(self.proj, ".git", "info", "exclude"), os.path.join(self.home, "notes.md")):
            self.ok("write_file", path=t, content="one\n", make_dirs=True)
            self.ok("edit_file", path=t, old_string="one", new_string="two")
            with open(t) as f:
                self.assertEqual(f.read(), "two\n")
            self.assertEqual(self.audit_ends()[-1]["how"], "python")


class LegacyPolicy(Base):
    def test_a_0_6_policy_still_loads(self):
        with open(os.path.join(ROOT, "tests", "policy-0.6.0.json")) as f:
            old = json.load(f)
        old.update(shell=["/bin/bash", "-c"], session_shell=["/bin/bash", "--norc", "--noprofile", "-i"],
                   tmux="tmux", tmux_socket=self.socket, default_cwd=self.home, state_dir=os.path.join(self.tmp, "state"),
                   protected_folders=[self.protected], sandbox_exec=os.path.join(self.tmp, "fake-sandbox-exec"),
                   sandbox_selftest=False)
        old["deny_paths"] = old["deny_paths"] + [os.path.join(self.tmp, "state")]
        with open(self.policy_file, "w") as f:
            json.dump(old, f)
        M._P = None
        P = M.policy()
        self.assertEqual(P["protected_folders"], [os.path.realpath(self.protected)])
        self.assertIn(os.path.realpath(os.path.expanduser("~/.zshrc")), P["protected_paths"])
        self.assertIn(os.path.realpath(os.path.expanduser("~/.local/bin")), P["protected_paths"])      # 0.7's added
        self.assertIn("/[.]claude[.]json$", P["protected_writes"])
        self.assertIn(os.path.realpath(os.path.expanduser("~/.config/gh")), P["deny_paths"])
        self.assertIn("include 0.7's defaults", "; ".join(P["_legacy"]))
        for k in ("approvals", "confirm_tools", "always_ask", "grant_minutes", "allow_repeat_minutes", "grant_hint",
                  "always_ask_paths"):
            self.assertNotIn(k, P)
        legacy = "; ".join(P["_legacy"])
        self.assertIn("always_ask_paths is read as protected_paths", legacy)
        self.assertIn("approvals", legacy)
        self.assertIn("grant_extra_write", legacy)
        t = self.ok("status")
        self.assertIn("older policy keys (0.6 and before): ignored: allow_repeat_minutes, always_ask", t)
        self.assertIn("is protected", self.refused("write_file", path=os.path.join(self.protected, "x"), content="x",
                                                   make_dirs=True))
        self.assertIn("still-works", self.ok("run", command="echo still-works"))

    def test_protected_paths_wins_over_the_old_name(self):
        self.set_policy(always_ask_paths=["~/.old"], protected_paths=["~/.new"])
        P = M.policy()
        self.assertEqual(P["protected_paths"][0], os.path.realpath(os.path.expanduser("~/.new")))
        self.assertEqual(P["_legacy"][0], "ignored: always_ask_paths")
        self.assertNotIn(os.path.realpath(os.path.expanduser("~/.old")), P["protected_paths"])

    def test_unknown_keys_are_still_refused(self):
        self.set_policy(grant_minutes=5, approvalz="tiers")
        with self.assertRaises(SystemExit) as e:
            M.policy()
        self.assertIn("approvalz", str(e.exception))
        self.assertNotIn("grant_minutes", str(e.exception))
        for bad in ({"sandbox_fail": "ask"}, {"network": "yes"}):
            M._P = None
            with open(self.policy_file, "w") as f:
                json.dump(bad, f)
            with self.assertRaises(SystemExit):
                M.policy()


@unittest.skipUnless(HAVE_TMUX, "needs tmux")
class Status(Base):
    def test_status(self):
        self.ok("run", command="echo password=hunter2-secret >/dev/null")
        self.ok("run", command="true", outside_sandbox=True, why="the user asked for it")
        self.refused("run", command="sudo true")
        self.ok("session_start", name="st1")
        t = self.ok("status")
        self.assertIn(f"Mac Terminal MCP {M.VERSION} (mac-terminal): no dialogs", t)
        self.assertIn("fence: working", t)
        self.assertIn("network: on", t)
        self.assertIn(f"protected folders: {os.path.realpath(self.protected)}", t)
        self.assertIn("outside_sandbox: allowed", t)
        self.assertIn("sessions: 1 (st1: fenced)", t)
        self.assertIn("by day (local): calls | fenced | unsandboxed | refused", t)
        self.assertRegex(t, r"\n  \d{4}-\d\d-\d\d: 4 \| 2 \| 1 \| 1(\n|$)")
        self.assertNotIn("hunter2", t)
        self.assertNotIn("older policy keys", t)


class SandboxFail(Base):
    """No sandbox-exec (as off a Mac): the self-test fails, and fenced calls follow sandbox_fail."""

    def policy_extra(self):
        return {"sandbox_exec": os.path.join(self.tmp, "missing"), "sandbox_selftest": True}

    def test_refuse_by_default(self):
        t = self.refused("run", command="touch f1")
        self.assertIn("isn't working on this Mac", t)
        self.assertIn("macOS only", t)
        self.refused("session_start", name="s", command="touch f2")
        self.assertFalse(os.path.exists(os.path.join(self.home, "f1")))
        st = self.ok("status")
        self.assertIn("fence: NOT working", st)
        self.assertIn("shell commands are refused (policy sandbox_fail: refuse)", st)
        p = os.path.join(self.home, "r.txt")
        self.ok("write_file", path=p, content="files still work\n")
        self.assertIn("files still work", self.ok("read_file", path=p))
        self.assertIn("by-request", self.ok("run", command="echo by-request", outside_sandbox=True,
                                            why="the user asked to run it anyway"))


class SandboxFailUnsandboxed(Base):
    def policy_extra(self):
        return {"sandbox_exec": os.path.join(self.tmp, "missing"), "sandbox_selftest": True,
                "sandbox_fail": "unsandboxed"}

    def test_runs_unsandboxed_and_says_so(self):
        t = self.ok("run", command="echo hi")
        self.assertIn("UNSANDBOXED (the sandbox self-test failed here; policy sandbox_fail: unsandboxed)", t)
        self.assertEqual(self.audit_ends()[-1]["how"], "unsandboxed")
        self.assertIn("shell commands run UNSANDBOXED", self.ok("status"))


@unittest.skipUnless(ON_MAC and HAVE_TMUX and os.access("/usr/bin/sandbox-exec", os.X_OK), "macOS sandbox only")
class MacSandbox(Base):
    """The real Seatbelt sandbox, through tmux, as installed. Skipped (with the reason) if its self-test fails here:
    then fenced calls are refused, which status shows. The fence writes only proj and temp here, so a probe in the
    real home folder stands for 'outside the folders it may write'."""

    def policy_extra(self):
        self.proj = os.path.join(self.home, "proj")
        os.makedirs(os.path.join(self.proj, ".git"))
        self.rc = os.path.join(self.proj, "rc-file")
        return {"sandbox_exec": "/usr/bin/sandbox-exec", "sandbox_selftest": True, "shell": ["/bin/bash", "-c"],
                "fence_writable": [self.proj], "protected_paths": [self.rc]}

    def setUp(self):
        super().setUp()
        self.wait_for_selftest()

    def wait_for_selftest(self):
        M.policy()                                      # load first: loading starts a fresh self-test box
        M.start_selftest()
        M._SB["done"].wait(90)
        st = M.sandbox_status()
        if not st["ok"]:
            self.skipTest(f"sandbox self-test failed here: {st['reason']}")

    def probe(self):
        p = os.path.join(os.path.expanduser("~"), f".mac-terminal-test-probe-{os.getpid()}")
        self.addCleanup(lambda: os.path.exists(p) and os.remove(p))
        return p

    def test_fence_writes_its_folders_and_nothing_protected(self):
        probe = self.probe()
        t = self.ok("run", command=f"touch ok; touch {probe}; touch rc-file; mkdir -p .git/hooks; touch .git/hooks/x; "
                                   f"mkdir -p {self.protected}; touch {self.protected}/y; true", cwd=self.proj)
        self.assertIn("fenced: macOS sandbox", t)
        self.assertTrue(os.path.exists(os.path.join(self.proj, "ok")))
        for p in (probe, self.rc, os.path.join(self.proj, ".git", "hooks", "x"), os.path.join(self.protected, "y")):
            self.assertFalse(os.path.exists(p), p)

    def test_outside_sandbox_writes_where_the_fence_cannot(self):
        probe = self.probe()
        self.ok("run", command=f"touch {probe}", outside_sandbox=True, why="test: the user asked for this file")
        self.assertTrue(os.path.exists(probe))

    def test_network_follows_the_policy(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        with open(os.path.join(self.proj, "probe.py"), "w") as f:
            f.write("import socket\ntry:\n socket.create_connection(('127.0.0.1', %d), 3); print('CONN' + 'ECTED')\n"
                    "except Exception as e:\n print('BLOCK' + 'ED', type(e).__name__)" % port)
        try:
            self.assertIn("CONNECTED", self.ok("run", command=f"{sys.executable} -I probe.py", cwd=self.proj))
            self.set_policy(network=False)
            self.wait_for_selftest()
            self.assertIn("BLOCKED", self.ok("run", command=f"{sys.executable} -I probe.py", cwd=self.proj))
        finally:
            srv.close()

    def test_exec_guard(self):
        """osascript and open can't start in the fence, even from inside a script."""
        with open(os.path.join(self.proj, "probe.sh"), "w") as f:
            f.write("/usr/bin/osascript -e 'return 7'; echo osa-rc=$?\n/usr/bin/open; echo open-rc=$?\n")
        t = self.ok("run", command="bash probe.sh", cwd=self.proj)
        self.assertIn("osa-rc=126", t)
        self.assertIn("open-rc=126", t)

    def test_two_self_tests_at_once_both_pass(self):
        """v0.3.2: two servers starting together (two chats) shared the self-test's folders, and one failed."""
        out = [None, None]

        def one(i):
            out[i] = M._selftest()
        ts = [threading.Thread(target=one, args=(i,)) for i in (0, 1)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertTrue(all(s["ok"] for s in out), [s["reason"] for s in out])

    def test_git_works_but_dot_git_and_config_files_are_protected(self):
        shutil.rmtree(os.path.join(self.proj, ".git"))
        subprocess.run("git init -q && git -c user.email=e@x -c user.name=n commit -q --allow-empty -m i",
                       shell=True, cwd=self.proj, check=True)       # git init creates .git: unsandboxed, here
        t = self.ok("run", command="echo a > f && git add f && git -c user.email=e@x -c user.name=n commit -qm t "
                                   "&& echo commit-ok", cwd=self.proj)
        self.assertIn("commit-ok", t)
        self.ok("run", command="mv .git .git-x && mkdir -p .git-x/hooks && echo x > .git-x/hooks/post-commit && "
                               "mv .git-x .git; true", cwd=self.proj)
        self.assertTrue(os.path.isdir(os.path.join(self.proj, ".git", "objects")))
        self.assertFalse(os.path.exists(os.path.join(self.proj, ".git-x")))
        self.assertFalse(os.path.exists(os.path.join(self.proj, ".git", "hooks", "post-commit")))
        self.ok("run", command="mkdir -p .vscode .claude; echo x > .vscode/tasks.json; echo x > .mcp.json; "
                               "echo x > .claude/settings.json; echo x > .GIT/config; true", cwd=self.proj)
        for rel in (".vscode/tasks.json", ".mcp.json", ".claude/settings.json"):
            self.assertFalse(os.path.exists(os.path.join(self.proj, rel)), rel)
        with open(os.path.join(self.proj, ".git", "config")) as f:
            self.assertNotEqual(f.read(), "x\n")

    def test_reads_cannot_see_denied_folders_even_past_the_deny_list(self):
        os.makedirs(os.path.join(self.tmp, "secret"))
        with open(os.path.join(self.tmp, "secret", "k"), "w") as f:
            f.write("very-secret-value")
        t = self.ok("run", command=f"cat {self.tmp}/secre?/k || echo cat-refused")   # a glob gets past the text match
        self.assertIn("fenced: macOS sandbox", t)
        self.assertNotIn("very-secret-value", t)
        self.assertRegex(t, r"(?m)^cat-refused$")                    # a printed line, not the command echoed back

    def test_tmux_is_unreachable_from_the_fence(self):
        probe = self.probe()
        T = M.tmux_exe()
        t = self.ok("run", command=f"{T} -L {self.socket} list-sessions -F reached-it; echo tmux-rc=$?; "
                                   f"{T} -L {self.socket} new-window 'touch {probe}'; true", cwd=self.proj)
        self.assertNotRegex(t, r"(?m)^reached-it$")    # run echoes the command, so look for a printed line only
        self.assertNotIn("tmux-rc=0", t)
        time.sleep(1)
        self.assertFalse(os.path.exists(probe))                              # new-window would run unsandboxed
        t = self.ok("run", command=f"{T} -L {self.socket} list-sessions -F reached-it", outside_sandbox=True,
                    why="test: the same client, unsandboxed")
        self.assertRegex(t, r"(?m)^reached-it$")
        self.assertIn("tmux unreachable", "; ".join(M.sandbox_status()["checks"]))

    def test_a_fenced_session_cannot_drive_tmux(self):
        probe = self.probe()
        self.ok("session_start", name="ft", cwd=self.proj)
        self.ok("session_send", name="ft", text=f"{M.tmux_exe()} -L {self.socket} run-shell 'touch {probe}'", wait_s=3)
        time.sleep(1)
        self.assertFalse(os.path.exists(probe))

    def test_a_session_keeps_the_fence(self):
        probe = self.probe()
        self.ok("session_start", name="fs", cwd=self.proj)
        self.ok("session_send", name="fs", text=f"touch inside; touch {probe}", wait_s=3)
        self.assertTrue(os.path.exists(os.path.join(self.proj, "inside")))
        self.assertFalse(os.path.exists(probe))


if __name__ == "__main__":
    unittest.main()
