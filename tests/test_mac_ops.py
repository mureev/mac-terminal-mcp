"""Tests for mac_ops_server.py. Standard library only; they need tmux and git, and run on Linux or macOS:

    python3 -B -m unittest discover -s tests -v

The shell is bash here (tests must not depend on the Mac's zsh setup); macOS-only tools (keep_awake, notify, open)
are skipped elsewhere. Every test uses its own tmux socket and state directory.
"""
from __future__ import annotations

import json
import os
import re
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
import mac_ops_server as M  # noqa: E402

HAVE_TMUX = shutil.which("tmux") is not None
ON_MAC = sys.platform == "darwin"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mac-ops-test-")
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        self.socket = f"mac-ops-test-{os.getpid()}-{id(self) % 100000}"
        self.protected = os.path.join(self.tmp, "protected")
        pol = {
            "shell": ["/bin/bash", "-c"],
            "session_shell": ["/bin/bash", "--norc", "--noprofile", "-i"],
            "tmux_socket": self.socket,
            "default_cwd": self.home,
            "state_dir": os.path.join(self.tmp, "state"),
            "protected_folders": [self.protected],
            "deny_paths": ["~/.ssh", os.path.join(self.tmp, "state"), os.path.join(self.tmp, "secret")],
            "confirm_tools": [],
        }
        pol.update(self.policy_extra())
        self.policy_file = os.path.join(self.tmp, "policy.json")
        with open(self.policy_file, "w") as f:
            json.dump(pol, f)
        os.environ["MAC_OPS_POLICY"] = self.policy_file
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


class Protocol(Base):
    def test_handshake_and_tools(self):
        r = M.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        self.assertEqual(r["result"]["serverInfo"]["name"], "mac-ops")
        self.assertEqual(r["result"]["protocolVersion"], "2025-06-18")
        names = [t["name"] for t in M.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})["result"]["tools"]]
        for n in ("run", "session_start", "session_send", "session_read", "session_list", "session_stop",
                  "read_file", "write_file", "open", "notify", "keep_awake",
                  "request_grant", "revoke_grant", "approval_status"):
            self.assertIn(n, names)
        # 0.4.0: no remote-host tools; nothing here reaches a host
        self.assertFalse([n for n in names if n.startswith("hosts_")], names)
        self.assertNotIn("hosts_apply", M.load_policy(None)["confirm_tools"])
        for t in M.tools():
            self.assertFalse(t["inputSchema"]["additionalProperties"], t["name"])
            self.assertIn("annotations", t)

    def test_unknown_argument_and_tool(self):
        self.refused("run", command="true", force=True)
        self.refused("nope")

    def test_stdio_roundtrip(self):
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        p = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "mac_ops_server.py")],
                           input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True,
                           env={**os.environ, "MAC_OPS_POLICY": self.policy_file}, timeout=20)
        lines = [json.loads(x) for x in p.stdout.splitlines()]
        self.assertEqual([x["id"] for x in lines], [1, 2])

    def test_bad_policy_key_stops_the_server(self):
        with open(self.policy_file, "w") as f:
            json.dump({"shel": ["/bin/sh", "-c"]}, f)
        p = subprocess.run([sys.executable, "-I", "-B", os.path.join(ROOT, "mac_ops_server.py")], input="",
                           capture_output=True, text=True, env={**os.environ, "MAC_OPS_POLICY": self.policy_file})
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
        t = self.ok("run", command="echo in:${TMUX:+tmux}; echo to-stderr >&2; exit 4")
        self.assertIn("in:tmux", t)
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
        recs = [json.loads(x) for x in log.splitlines()]
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
            f.write(tiny_pdf("Hello from mac-ops"))
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
        self.assertIn("Hello from mac-ops", t)


class Confirm(Base):
    """The Mac dialog, replaced by a stub that answers what the test wrote to a file and keeps what it was shown."""

    def policy_extra(self):
        self.answer = os.path.join(self.tmp, "answer")
        self.seen = os.path.join(self.tmp, "seen")
        stub = os.path.join(self.tmp, "dialog")
        with open(stub, "w") as f:
            f.write(f'#!/bin/bash\nprintf "%s" "$1" > {self.seen!r}\ncat {self.answer!r} 2>/dev/null || echo timeout\n')
        os.chmod(stub, 0o755)
        return {"confirm_with": stub, "confirm_timeout_s": 5, "approvals": "every",
                "confirm_tools": ["run", "session_start", "session_send", "write_file"]}

    def say(self, answer):
        with open(self.answer, "w") as f:
            f.write(answer)

    def test_allow_runs_and_shows_the_command(self):
        self.say("Allow")
        self.assertIn("hello-42", self.ok("run", command="echo hello-$((40+2))"))
        with open(self.seen) as f:
            self.assertIn("echo hello-$((40+2))", f.read())

    def test_deny_timeout_and_garbage_refuse_and_nothing_runs(self):
        marker = os.path.join(self.home, "ran")
        for answer in ("Deny", "timeout", "allow", ""):
            self.say(answer)
            self.assertIn("did not allow", self.refused("run", command=f"touch {marker}"))
            self.assertFalse(os.path.exists(marker), answer)
        os.remove(self.answer)                              # stub prints its fallback
        self.refused("run", command=f"touch {marker}")
        self.assertFalse(os.path.exists(marker))

    def test_newlines_cannot_hide_part_of_a_command(self):
        self.say("Deny")
        self.refused("run", command="echo harmless" + "\n" * 40 + "rm -rf ~/somewhere")
        with open(self.seen) as f:
            seen = f.read()
        self.assertIn("rm -rf ~/somewhere", seen)
        self.assertLess(seen.count("\n"), 10)

    def test_write_file_creates_no_folder_before_allow(self):
        self.say("Deny")
        f = os.path.join(self.home, "newdir", "x.txt")
        self.refused("write_file", path=f, content="x", make_dirs=True)
        self.assertFalse(os.path.exists(os.path.dirname(f)))

    def test_edit_file_asks_and_does_not_write_over_a_change_made_meanwhile(self):
        f = os.path.join(self.home, "c.txt")
        with open(f, "w") as fh:
            fh.write("alpha\nbeta\n")
        self.say("Deny")
        self.assertIn("did not allow", self.refused("edit_file", path=f, old_string="beta", new_string="gamma"))
        with open(self.seen) as fh:
            self.assertIn("beta", fh.read())                            # the dialog showed the change
        real = M.show_dialog

        def meanwhile(*a, **k):
            with open(f, "a") as fh:
                fh.write("his own edit\n")
            return "Allow"
        M.show_dialog = meanwhile
        try:
            self.assertIn("changed while", self.refused("edit_file", path=f, old_string="beta", new_string="gamma"))
        finally:
            M.show_dialog = real
        with open(f) as fh:
            self.assertEqual(fh.read(), "alpha\nbeta\nhis own edit\n")

    def test_refusals_and_answers_are_audited(self):
        self.say("Deny")
        self.refused("run", command="true")
        with open(os.path.join(self.tmp, "state", "audit.jsonl")) as f:
            phases = [json.loads(x)["phase"] for x in f.read().splitlines()]
        self.assertEqual([x for x in phases if x != "selftest"], ["start", "confirm", "end"])

    def test_read_only_tools_do_not_ask(self):
        os.remove(self.answer) if os.path.exists(self.answer) else None
        p = os.path.join(self.home, "r.txt")
        with open(p, "w") as f:
            f.write("x")
        self.ok("read_file", path=p)

    @unittest.skipUnless(HAVE_TMUX, "needs tmux")
    def test_sessions_ask(self):
        self.say("Deny")
        self.refused("session_start", name="s1", command="echo hi")
        self.say("Allow")
        self.ok("session_start", name="s1")
        self.say("Deny")
        self.refused("session_send", name="s1", text="echo hi")


@unittest.skipUnless(HAVE_TMUX, "needs tmux")
class Sessions(Base):
    def test_job_session(self):
        t = self.ok("session_start", name="job1", command="echo one; sleep 1; echo two; exit 3", wait_s=15)
        self.assertIn("two", t)
        self.assertIn("[mac-ops: exit 3]", t)
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


# ------------------------------------------------------------------------------------------------- v0.3 approvals --
READS = [
    "ls -la", "ls -la ~/Documents | head -20", "cat README.md", "grep -rn 'def ' . | wc -l", "rg -n 'foo|bar' src",
    "find . -name '*.py' -type f", "git status", "git -C repo log --oneline -5", "git diff HEAD~1 -- x.py",
    "git branch -a", "git branch --list 'feat*'", "git config --get user.email", "git remote -v",
    "ps aux | grep python", "du -sh * 2>/dev/null | sort -h", "head -n 50 file.log 2>&1", "echo $HOME",
    "cd sub && ls", "sed -n '1,20p' file", "tail -n 100 /var/log/system.log", "wc -l < file.txt", "stat -f %z f",
    "/usr/bin/git log -1", "jq '.a' x.json", "tar -tzf a.tgz",
    "git log --format='%h %s' -3", "test -f x && echo yes || echo no", "cat 'a b.txt'", "grep 'x;y' f",
    "grep '|' file", "git show HEAD:README.md", "ls\nwc -l x", "pgrep -fl Claude", "ps aux", "ps -ef",
    # v0.5.2: harmless env prefixes, $ and ` inside single quotes, ioreg
    "GIT_OPTIONAL_LOCKS=0 git status --short", "GIT_OPTIONAL_LOCKS=0 git log --oneline | head -15; echo; du -sh x",
    "LC_ALL=C sort x", "TZ=UTC date", "cut -d= -f1 f.env | grep -v '^#' | grep -v '^$'", "sed -n '/a/,$p' f",
    "grep '`x`' f", "grep '$(x)' f", "ioreg -l -w0", "grep -i -E 'block|security|install.sh' /tmp/x",
    "rg -n 'osascript|killall|profiles' src",
]
NOT_READS = [
    "ls > out.txt", "cat x >> y", "echo $(whoami)", "echo `id`", "rm -rf build", "find . -name x -delete",
    "find . -exec rm {} \\;", "git -c core.pager=sh log", "git log --output=/tmp/x", "git diff --ext-diff",
    "git branch newbranch", "git branch -D old", "git tag v1", "git config user.name x", "git stash",
    "git checkout main", "git commit -m x", "git remote add o url", "git remote show https://x.example",
    "sed -i '' s/a/b/ f", "sed -ni p f", "sort -o out in", "awk '{print}' f", "python3 -c 'print(1)'", "node -e 1",
    "xargs rm < list", "FOO=1 ls", "ls &", "(ls)", "{ ls; }", "ls; touch x", "ls | tee out", "open https://x",
    "curl https://x", "make", "npm test", "bash -c ls", "sh script.sh", "./run.sh", "/tmp/evil/ls",
    "/usr/bin/../../tmp/x", "ls $'\\x41'", "cat <(ls)", "cat <<EOF\nx\nEOF", "rg --pre=cat x", "fd -x rm",
    "tree -o out", "base64 -o out in", "tar -xzf a.tgz", "unzip a.zip", "brew install x", "brew upgrade",
    "kill 1", "env", "printenv", "pbpaste", "ls 2>/dev/null/../x", "echo ok > /dev/null.txt", "git grep -Ocat x",
    "xattr -w a b f", "codesign -s - f", "sysctl -w a=1", "chmod +x f", "touch f", "mkdir d", "cp a b", "mv a b",
    "ln -s a b", "git log -p | less", "tail -f x | sh", "ls ${HOME:-$(id)}", "eval ls", "exec ls", "source x",
    "zsh -c ls", "command ls", "nohup ls", "time rm x", "echo \"$(id)\"", "cat x|&tee y", "ls>x",
    "ls # comment > here", "ls\rrm -rf x", "ps eww", "ps -E", "jq -n env", "launchctl print gui/501",
    "defaults read", "plutil -p x.plist", "brew config", "sort --compress-program=sh x",
    "echo $AWS_SECRET_ACCESS_KEY", "printf %s ${GITHUB_TOKEN}", "echo $parameters", "ps -axE", "ps -Ewwax",
    "echo $HOMEBREW_GITHUB_API_TOKEN",
    # v0.5.2: only harmless prefixes; quotes only hide what single quotes hide
    "PAGER=sh git log", "GIT_PAGER=sh git log", "GIT_EXTERNAL_DIFF=x git diff", "GIT_OPTIONAL_LOCKS=$(id) git status",
    "TZ=a;b date", "LANG=C", "echo \"$(id)\"", "echo \"`id`\"", "echo \"'$(id)'\"", "echo '' $(id)", "ls $'\\x41'",
    "echo \\'$(id)'", "GIT_OPTIONAL_LOCKS=0 git commit -m x",
]
TIER2 = [
    "git push", "git push --force origin main", "cd x && git push", "gh pr create -t x", "gh api repos/x",
    "aws s3 ls", "kubectl get pods", "terraform apply", "docker ps", "curl -X POST https://x -d @f",
    "curl -d a=b https://x", "npm publish", "launchctl bootout gui/501/x", "crontab -l", "defaults write com.x k v",
    "security find-certificate", "osascript -e 'tell app \"Finder\" to quit'", "killall Dock",
    "open -a Terminal x.command", "cd x && open report.html", "/usr/bin/open https://x",
    "rsync -a . host:/x", "git reset --hard HEAD~1", "git clean -fd", "pmset sleepnow",
    # v0.5.2: programs in any position that runs them
    "security find-generic-password", "/usr/bin/security x", "sudo security x", "env -i security x",
    "ls; security x", "echo x | xargs killall", "find . -exec security {} \\;", "bash -c 'osascript -e 1'",
    "zsh -lc \"killall Dock\"", "time nvram -p", "X=1 tccutil reset All", "if true; then pkill x; fi",
    "echo $(security x)", "cd mac-ops && ./install.sh", "bash mac-ops/install.sh", "sh ~/x/mac-ops/install.sh --check",
    "echo 'unclosed security",
]
NOT_TIER2 = [
    "grep -i -E 'block|security' /tmp/x", "rg -n security notes.md", "cat > \"$T/bin/security\" <<'EOF'\nx\nEOF",
    "bash tools/logs/install.sh --check", "cd mytool && ./install.sh", "ls srt-0.0.81-profiles.json",
    "grep -c killall log", "echo osascript", "git log --grep=nvram",
]


class Classify(Base):
    def test_reads(self):
        for c in READS:
            self.assertEqual(M.classify(c), ("read", ""), c)

    def test_not_reads(self):
        for c in NOT_READS:
            self.assertNotEqual(M.classify(c)[0], "read", c)

    def test_tier2(self):
        for c in TIER2:
            self.assertEqual(M.classify(c)[0], "tier2", c)

    def test_not_tier2(self):
        for c in NOT_TIER2:
            self.assertNotEqual(M.classify(c)[0], "tier2", c)

    def test_install_sh_asks_only_in_a_mac_ops_folder(self):
        d = os.path.join(self.tmp, "mac-ops")
        os.makedirs(d)
        self.assertEqual(M.classify("./install.sh --check", d), ("tier2", "reinstall Mac Ops"))
        self.assertEqual(M.classify("bash install.sh", d)[0], "tier2")
        self.assertNotEqual(M.classify("./install.sh --check", self.home)[0], "tier2")


class Tiers(Base):
    """Approvals 'tiers' with a stand-in sandbox-exec (records the profile, then runs the command unsandboxed) and the
    dialog stub. Enforcement by the real sandbox is tested on the Mac (MacSandbox)."""

    def policy_extra(self):
        self.answer = os.path.join(self.tmp, "answer")
        self.seen = os.path.join(self.tmp, "seen")
        self.count = os.path.join(self.tmp, "dialogs")
        self.prof = os.path.join(self.tmp, "profile")
        stub = os.path.join(self.tmp, "dialog")
        with open(stub, "w") as f:
            f.write(f'#!/bin/bash\nprintf "%s" "$1" > {self.seen!r}\nshift 2\necho "$*" >> {self.count!r}\n'
                    f'cat {self.answer!r} 2>/dev/null || echo timeout\n')
        sbx = os.path.join(self.tmp, "fake-sandbox-exec")
        with open(sbx, "w") as f:
            f.write(f'#!/bin/bash\n[ "$1" = -f ] || exit 64\ncat "$2" > {self.prof!r}\nshift 2\nexec "$@"\n')
        for x in (stub, sbx):
            os.chmod(x, 0o755)
        self.proj = os.path.join(self.home, "proj")
        os.makedirs(os.path.join(self.proj, ".git"))
        return {"confirm_with": stub, "confirm_timeout_s": 5, "sandbox_exec": sbx, "sandbox_selftest": False,
                "confirm_tools": ["run", "session_start", "session_send", "write_file", "open"]}

    def say(self, answer):
        if answer is None:
            if os.path.exists(self.answer):
                os.remove(self.answer)
            return
        with open(self.answer, "w") as f:
            f.write(answer)

    def dialogs(self):
        try:
            with open(self.count) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def profile(self):
        with open(self.prof) as f:
            return f.read()

    def grant(self, folders=None, network=False):
        self.say("Allow")
        t = self.ok("request_grant", purpose="test task", folders=folders or [self.proj], network=network)
        self.say(None)
        return re.search(r'grant="(g-[0-9a-f]{12})"', t).group(1)

    def test_reads_run_sandboxed_without_a_dialog(self):
        t = self.ok("run", command="echo read-ok | cat")
        self.assertIn("read-ok", t)
        self.assertIn("read-only sandbox", t)
        self.assertEqual(self.dialogs(), [])
        p = self.profile()
        self.assertIn("(deny network*)", p)
        self.assertNotIn(self.proj, p)
        st = os.path.realpath(os.path.join(self.tmp, "state"))
        self.assertIn(f'(deny file-read-data (subpath "{st}") (regex #"{M.ci_path_rx(st)}(/|$)"))', p)   # contents denied, metadata not: programs
        self.assertNotIn(f'(deny file-read* (subpath "{st}")', p)      # fstat() their output file in there

    def test_tier1_asks_and_allow_once_runs_unsandboxed(self):
        self.say("Allow Once")
        if os.path.exists(self.prof):
            os.remove(self.prof)
        self.ok("run", command="touch made-once")
        self.assertTrue(os.path.exists(os.path.join(self.home, "made-once")))
        self.assertFalse(os.path.exists(self.prof))                 # no sandbox for an allowed-once call
        self.assertEqual(self.dialogs(), ["Don’t Allow Allow Once"])
        with open(self.seen) as f:
            seen = f.read()
        self.assertTrue(seen.startswith("Claude wants to run a command\n\ntouch made-once\nin "), seen)
        self.assertNotIn("More Options", seen)
        self.assertEqual(M.GRANTS, {})                                  # a dialog never opens a grant (0.5.1)
        self.assertIn(f"\n\nFrom mac-ops {M.VERSION} in ", seen)

    def test_request_grant_scope_and_revocation(self):
        tok = self.grant()
        self.ok("write_file", path=os.path.join(self.proj, "in.txt"), content="x", grant=tok)
        self.ok("session_start", name="g1", cwd=self.proj, grant=tok)
        self.assertEqual(len(self.dialogs()), 1)                    # only request_grant's
        out = os.path.join(self.home, "out.txt")
        self.assertIn("did not allow", self.refused("write_file", path=out, content="x", grant=tok))
        self.assertFalse(os.path.exists(out))
        t = self.refused("run", command="touch again", cwd=self.proj, grant=tok)   # the deny revoked the grant
        self.assertIn("did not allow", t)
        self.assertEqual(len(self.dialogs()), 3)

    def test_grant_dialog_words(self):
        self.grant()
        with open(self.seen) as f:
            seen = f.read()
        self.assertTrue(seen.startswith("Let Claude work in \u201cproj\u201d for 60 minutes?\n\nTask: test task\n"), seen)
        self.assertIn("Network: off \u00b7 this chat only \u00b7 until ", seen)
        self.assertIn("Pushes, production and other risky actions still ask.", seen)
        self.assertEqual(self.dialogs()[-1], "Don\u2019t Allow Allow for 60 Minutes")

    def test_dialog_script_is_an_alert_with_dont_allow_as_default(self):
        sc = M.dialog_script([M.NO, M.ONCE], True)
        self.assertIn("display alert (item 1 of argv) message (item 2 of argv) as critical", sc)
        self.assertIn('default button "Don\u2019t Allow" cancel button "Don\u2019t Allow"', sc)
        self.assertNotIn("as critical", M.dialog_script([M.NO, M.ONCE], False))

    def test_network_flag_reaches_the_profile(self):
        tok = self.grant(network=True)
        self.ok("run", command="touch n1", cwd=self.proj, grant=tok)
        self.assertNotIn("(deny network*)", self.profile())
        self.ok("run", command="cat n1", cwd=self.proj, grant=tok)       # a read keeps the read-only profile
        self.assertIn("(deny network*)", self.profile())

    def test_allowed_once_repeats_without_a_dialog_for_a_while(self):
        self.say("Allow Once")
        self.ok("run", command="touch r1", cwd=self.proj)
        self.say(None)                                                 # no answer: a dialog now would refuse
        self.ok("run", command="touch r1", cwd=self.proj)              # identical: no dialog
        self.assertEqual(len(self.dialogs()), 1)
        self.refused("run", command="touch r2", cwd=self.proj)         # different text asks
        self.refused("run", command="touch r1", cwd=self.home)         # different folder asks
        self.assertEqual(len(self.dialogs()), 3)

    def test_repeats_never_cover_tier2(self):
        self.say("Allow Once")
        self.ok("run", command="git push 2>/dev/null; true", cwd=self.proj)
        self.say(None)
        self.refused("run", command="git push 2>/dev/null; true", cwd=self.proj)
        self.assertEqual(len(self.dialogs()), 2)

    def test_repeat_window_off(self):
        M._P = None
        with open(self.policy_file) as f:
            pol = json.load(f)
        pol["allow_repeat_minutes"] = 0
        with open(self.policy_file, "w") as f:
            json.dump(pol, f)
        self.say("Allow Once")
        self.ok("run", command="touch r1", cwd=self.proj)
        self.ok("run", command="touch r1", cwd=self.proj)
        self.assertEqual(len(self.dialogs()), 2)

    def test_forgotten_grant_gets_a_hint_then_a_dialog(self):
        tok = self.grant()
        n = len(self.dialogs())
        t = self.refused("run", command="touch h1", cwd=self.proj)
        self.assertIn("a live grant (" + tok[:6], t)
        self.assertNotIn(tok, t)                                       # never the whole token
        self.assertEqual(len(self.dialogs()), n)                       # the hint shows no dialog
        self.ok("run", command="touch h1", cwd=self.proj, grant=tok)   # with the token: no dialog
        self.assertEqual(len(self.dialogs()), n)
        t = self.refused("run", command="cd proj && touch h3", cwd=self.home)  # cd DIR && counts as the folder
        self.assertIn("a live grant", t)
        self.assertEqual(len(self.dialogs()), n)
        self.say("Allow Once")
        self.ok("run", command="cd proj && touch h3", cwd=self.home)    # the same call again asks
        self.assertEqual(len(self.dialogs()), n + 1)
        self.assertTrue(os.path.exists(os.path.join(self.proj, "h3")))

    def test_no_hint_outside_the_grant_folders(self):
        self.grant()
        self.say(None)
        t = self.refused("run", command="touch x", cwd=self.home)
        self.assertIn("did not allow", t)

    def test_tier2_asks_even_with_a_grant_and_says_why(self):
        tok = self.grant()
        self.refused("run", command="git push origin main", cwd=self.proj, grant=tok)
        with open(self.seen) as f:
            self.assertTrue(f.read().startswith("Claude wants to push or rewrite git history\n"))
        self.assertEqual(self.dialogs()[-1], "Don’t Allow Allow Once")

    def test_protected_files_ask_even_inside_a_grant(self):
        tok = self.grant()
        os.makedirs(os.path.join(self.proj, ".git", "hooks"))
        self.refused("write_file", path=os.path.join(self.proj, ".git", "hooks", "pre-commit"), content="x",
                     grant=tok)
        with open(self.seen) as f:
            self.assertIn("Claude wants to change a file that runs later", f.read())

    def test_edit_file_under_a_grant_and_on_protected_files(self):
        f = os.path.join(self.proj, "app.py")
        with open(f, "w") as fh:
            fh.write("DEBUG = True\n")
        tok = self.grant()
        n = len(self.dialogs())
        t = self.ok("edit_file", path=f, old_string="True", new_string="False", grant=tok)
        self.assertIn("grant", t)
        self.assertEqual(len(self.dialogs()), n)                       # no dialog under the grant
        os.makedirs(os.path.join(self.proj, ".vscode"))
        with open(os.path.join(self.proj, ".vscode", "tasks.json"), "w") as fh:
            fh.write('{"x": 1}\n')
        self.refused("edit_file", path=os.path.join(self.proj, ".vscode", "tasks.json"), old_string="1",
                     new_string="2", grant=tok)                         # tier 2: asks (and the stub says no)
        with open(self.seen) as fh:
            self.assertIn("Claude wants to change a file that runs later", fh.read())
        self.ok("run", command="true", cwd=self.proj, grant=tok)       # the grant's sandbox profile
        prof = self.profile()
        for rx in ("/[.]git$", "/[.]vscode(/|$)", "/[.]mcp[.]json$"):
            self.assertIn(M.ci_rx(rx), prof)
        self.assertEqual(M.ci_rx("/[.]git$"), "/[.][gG][iI][tT]$")
        self.assertEqual(M.ci_path_rx("/a.b/C"), "^/[aA][.][bB]/[cC]")
        self.assertIsNone(M.ci_path_rx('/x"y'))

    def test_other_letter_case_is_still_protected(self):
        tok = self.grant()
        os.makedirs(os.path.join(self.proj, ".git", "hooks"), exist_ok=True)
        self.refused("write_file", path=os.path.join(self.proj, ".GIT", "Hooks", "pre-commit"), content="x",
                     grant=tok)                                         # tier 2, whatever the case
        if M.CASELESS:
            self.refused("read_file", path="~/.SSH/id_ed25519")
            self.assertIn("denied path", self.refused("run", command="cat ~/.SSH/id_ed25519"))

    def test_grant_folders_must_be_narrow(self):
        os.makedirs(os.path.join(self.protected, "playbooks"), exist_ok=True)
        for bad in (os.path.expanduser("~"), "/", self.tmp, os.path.join(self.tmp, "state"),
                    os.path.join(self.home, "nope"), self.protected, os.path.join(self.protected, "playbooks")):
            self.refused("request_grant", purpose="x", folders=[bad])
        self.assertEqual(self.dialogs(), [])

    def test_unknown_and_expired_tokens_are_ignored(self):
        self.say("Allow Once")
        t = self.ok("run", command="touch u1", grant="g-000000000000")
        self.assertIn("treated as having none", t)
        tok = self.grant()
        M.GRANTS[tok]["expires"] = 0
        self.say("Allow Once")
        self.assertIn("expired", self.ok("run", command="touch u2", cwd=self.proj, grant=tok))

    def test_sessions(self):
        self.ok("session_start", name="r1", command="echo ro-job", wait_s=10)
        self.ok("session_send", name="r1", key="C-c", wait_s=0)
        self.assertEqual(self.dialogs(), [])
        self.refused("session_send", name="r1", text="touch x1", wait_s=0)   # writing needs a grant: asks
        tok = self.grant()
        self.ok("session_start", name="g2", cwd=self.proj, grant=tok)
        self.ok("session_send", name="g2", text="touch inside", grant=tok, wait_s=3)
        self.ok("session_send", name="g2", text="echo a-read", wait_s=2)     # reads in a sandboxed session: free
        n = len(self.dialogs())
        self.refused("session_send", name="g2", text="touch other", wait_s=0)   # no grant passed: asks
        self.assertEqual(len(self.dialogs()), n + 1)

    def test_open_asks_for_files_and_web_addresses(self):
        self.say("Deny")
        script = os.path.join(self.home, "x.command")
        with open(script, "w") as f:
            f.write("#!/bin/sh\ntouch pwned\n")
        for args in ({"target": "https://example.com/?q=secret"}, {"target": "https://evil.example/exfil/abc"},
                     {"target": script}, {"target": self.home, "app": "Terminal"}):
            self.refused("open", **args)
        self.assertEqual(len(self.dialogs()), 4)
        self.call("open", target=self.proj)                     # a folder: no dialog (fails off a Mac: no open)
        self.call("open", app="Calculator")
        self.assertEqual(len(self.dialogs()), 4)

    def test_status_and_audit(self):
        self.ok("run", command="ls")
        tok = self.grant()
        t = self.ok("approval_status")
        self.assertIn("approvals: tiers", t)
        self.assertIn("active grants: 1", t)
        self.assertNotIn(tok, t)
        with open(os.path.join(self.tmp, "state", "audit.jsonl")) as f:
            log = f.read()
        self.assertNotIn(tok, log)                                   # tokens are masked in the audit log
        ends = [json.loads(x) for x in log.splitlines() if '"phase": "end"' in x]
        self.assertEqual(ends[0]["route"], "read")


class EveryFallback(Base):
    def policy_extra(self):
        self.answer = os.path.join(self.tmp, "answer")
        stub = os.path.join(self.tmp, "dialog")
        with open(stub, "w") as f:
            f.write(f'#!/bin/bash\ncat {self.answer!r} 2>/dev/null || echo timeout\n')
        os.chmod(stub, 0o755)
        return {"confirm_with": stub, "confirm_timeout_s": 5, "sandbox_exec": os.path.join(self.tmp, "missing"),
                "confirm_tools": ["run", "write_file"]}

    def test_without_a_working_sandbox_every_call_asks(self):
        self.refused("run", command="ls")                            # a read asks too
        with open(self.answer, "w") as f:
            f.write("Allow")
        self.assertIn("unsandboxed", self.ok("run", command="ls"))
        self.assertIn("every call asks", self.ok("approval_status"))
        self.refused("request_grant", purpose="x", folders=[self.home])


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


@unittest.skipUnless(ON_MAC and HAVE_TMUX and os.access("/usr/bin/sandbox-exec", os.X_OK), "macOS sandbox only")
class MacSandbox(Tiers.__base__):
    """The real Seatbelt sandbox, through tmux, as installed. Skipped (with the reason) if its self-test fails here:
    then the server runs approvals 'every' and asks for each call, which approval_status shows."""

    def policy_extra(self):
        self.answer = os.path.join(self.tmp, "answer")
        stub = os.path.join(self.tmp, "dialog")
        with open(stub, "w") as f:
            f.write(f'#!/bin/bash\ncat {self.answer!r} 2>/dev/null || echo timeout\n')
        os.chmod(stub, 0o755)
        self.proj = os.path.join(self.home, "proj")
        os.makedirs(os.path.join(self.proj, ".git"))
        return {"confirm_with": stub, "confirm_timeout_s": 5, "sandbox_exec": "/usr/bin/sandbox-exec",
                "sandbox_selftest": True, "shell": ["/bin/bash", "-c"],
                "confirm_tools": ["run", "session_start", "session_send", "write_file", "open"]}

    def setUp(self):
        super().setUp()
        M.start_selftest()
        M._SB["done"].wait(90)
        st = M.sandbox_status()
        if not st["ok"]:
            self.skipTest(f"sandbox self-test failed here: {st['reason']}")

    def grant(self, network=False):
        with open(self.answer, "w") as f:
            f.write("Allow")
        t = self.ok("request_grant", purpose="mac test", folders=[self.proj], network=network)
        os.remove(self.answer)
        return re.search(r'grant="(g-[0-9a-f]{12})"', t).group(1)

    def test_grant_writes_only_its_folder(self):
        tok = self.grant()
        probe = os.path.join(os.path.expanduser("~"), f".mac-ops-test-probe-{os.getpid()}")
        try:
            self.ok("run", command=f"touch ok; touch {probe}; mkdir -p .git/hooks; touch .git/hooks/x; true",
                    cwd=self.proj, grant=tok)
            self.assertTrue(os.path.exists(os.path.join(self.proj, "ok")))
            self.assertFalse(os.path.exists(probe))
            self.assertFalse(os.path.exists(os.path.join(self.proj, ".git", "hooks", "x")))
        finally:
            if os.path.exists(probe):
                os.remove(probe)

    def test_network_only_with_a_network_grant(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        code = ("import socket\ntry:\n socket.create_connection(('127.0.0.1', %d), 3); print('CONN' + 'ECTED')\n"
                "except Exception as e:\n print('BLOCK' + 'ED', type(e).__name__)" % port)
        path = os.path.join(self.proj, "probe.py")
        with open(path, "w") as f:
            f.write(code)
        try:
            t = self.ok("run", command=f"{sys.executable} -I probe.py", cwd=self.proj, grant=self.grant())
            self.assertIn("BLOCKED", t)
            st = M.sandbox_status()
            if st.get("network_grant") != "works":
                self.skipTest(f"network grants don't connect on this Mac yet: {st.get('network_grant')}")
            t = self.ok("run", command=f"{sys.executable} -I probe.py", cwd=self.proj, grant=self.grant(network=True))
            self.assertIn("CONNECTED", t)
        finally:
            srv.close()

    def test_exec_guard(self):
        """Typed as a command, osascript and open are tier 2 (they ask). From inside a script under a grant, which the
        classifier can't see into, the sandbox must refuse to start them."""
        with open(os.path.join(self.proj, "probe.sh"), "w") as f:
            f.write("/usr/bin/osascript -e 'return 7'; echo osa-rc=$?\n/usr/bin/open; echo open-rc=$?\n")
        t = self.ok("run", command="bash probe.sh", cwd=self.proj, grant=self.grant())
        self.assertIn("osa-rc=126", t)
        self.assertIn("open-rc=126", t)
        self.assertEqual(M.classify("/usr/bin/osascript -e 'return 7'")[0], "tier2")

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

    def test_git_works_but_dot_git_cannot_be_renamed(self):
        shutil.rmtree(os.path.join(self.proj, ".git"))
        subprocess.run("git init -q && git -c user.email=e@x -c user.name=n commit -q --allow-empty -m i",
                       shell=True, cwd=self.proj, check=True)
        tok = self.grant()
        t = self.ok("run", command="echo a > f && git add f && git -c user.email=e@x -c user.name=n commit -qm t "
                                   "&& echo commit-ok", cwd=self.proj, grant=tok)
        self.assertIn("commit-ok", t)
        self.ok("run", command="mv .git .git-x && mkdir -p .git-x/hooks && echo x > .git-x/hooks/post-commit && "
                               "mv .git-x .git; true", cwd=self.proj, grant=tok)
        self.assertTrue(os.path.isdir(os.path.join(self.proj, ".git", "objects")))
        self.assertFalse(os.path.exists(os.path.join(self.proj, ".git-x")))
        self.assertFalse(os.path.exists(os.path.join(self.proj, ".git", "hooks", "post-commit")))
        self.ok("run", command="mkdir -p .vscode; echo x > .vscode/tasks.json; echo x > .mcp.json; true",
                cwd=self.proj, grant=tok)
        self.assertFalse(os.path.exists(os.path.join(self.proj, ".vscode", "tasks.json")))
        self.assertFalse(os.path.exists(os.path.join(self.proj, ".mcp.json")))

    def test_reads_cannot_see_denied_folders_even_past_the_deny_list(self):
        os.makedirs(os.path.join(self.tmp, "secret"))
        with open(os.path.join(self.tmp, "secret", "k"), "w") as f:
            f.write("very-secret-value")
        t = self.ok("run", command=f"cat {self.tmp}/secre?/k || echo cat-refused")   # a glob gets past the text match
        self.assertIn("read-only sandbox", t)
        self.assertNotIn("very-secret-value", t)
        self.assertIn("cat-refused", t)



class DialogText(Base):
    """v0.5: the command made readable, never changed."""

    CMDS = ["a && b || c; d\ne", "echo 'x; y && z' \"q;w\" $(f; g) `h; i` {j; k;} && l", "echo \\; x", "",
            "cd \"$HOME/p q\" && P=/usr/bin/python3; $P cli.py count 'level:ERROR' 2>&1 | head -8; echo ===",
            "unterminated 'quote; rm -rf x", "a;;b", "x && \n\n\n y"]

    def test_steps_join_back_to_the_command(self):
        for c in self.CMDS:
            self.assertEqual("".join(M.split_steps(c)), c, c)
        self.assertEqual(M.steps_of("a && b || c; d\ne"), ["a &&", "b ||", "c;", "d", "e"])
        self.assertEqual(len(M.steps_of(self.CMDS[1])), 2)                 # quoted and nested separators stay
        self.assertEqual(M.steps_of("unterminated 'quote; rm -rf x"), ["unterminated 'quote; rm -rf x"])

    def test_every_step_is_shown_and_long_ones_say_what_they_leave_out(self):
        c = "; ".join(f"echo step{i}" for i in range(30)) + "; rm -rf ~/x"
        lines = M.step_lines(c)
        self.assertLessEqual(len(lines), 12)
        self.assertIn("rm -rf ~/x", lines[-1])
        self.assertIn("20 more steps", lines[8])
        self.assertEqual(M.step_lines("echo a\nb"), ["echo a\nb"] and M.step_lines("echo a\nb"))
        self.assertIn("\u23ce", M.step_lines("echo 'a\nb'")[0])                 # a newline inside quotes: shown

    def test_programs(self):
        self.assertEqual(M.programs(self.CMDS[4]), ["$P cli.py", "head"])
        self.assertEqual(M.programs("X=1 .venv/bin/python3 a/b.py run | cut -c1-9 2>&1"), ["python3 b.py", "cut"])

    def test_source_line_names_the_client_and_a_chat_when_meta_has_one(self):
        M.CLIENT["name"] = "local-agent-mode-mac-ops"
        self.addCleanup(M.CLIENT.update, name="")
        M.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                  "params": {"name": "approval_status", "arguments": {}, "_meta": {"sessionId": "s/abc12345678"}}})
        self.assertIn("in Cowork \u00b7 chat \u202612345678 \u00b7 process", M.source_line())
        M.call("approval_status", {}, None)
        self.assertNotIn("chat", M.source_line())

    def test_retired_more_options_keys_are_ignored(self):
        with open(self.policy_file, "w") as f:
            json.dump({"allow_all_minutes": [15], "dialog_folder_minutes": [60],
                       "state_dir": os.path.join(self.tmp, "state")}, f)
        M._P = None
        self.addCleanup(setattr, M, "_P", None)
        self.assertNotIn("allow_all_minutes", M.policy())

if __name__ == "__main__":
    unittest.main()
