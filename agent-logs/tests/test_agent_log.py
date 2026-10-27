"""agent-log: deduplication, correlation, verify, and the CLI over fixture data."""

import json
import os
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

L = helpers.load("agent-log")
D = helpers.load("agent-logd")

T0 = 1793136000.0
HOOK = "/usr/local/lib/agent-audit/claude-audit-hook"
GOOD_CLAUDE = "/opt/claude-code/2.1.312/claude"
_n = [0]


def sid():
    _n[0] += 1
    return f"x:{_n[0]}"


def base(env, t, source, event, **kw):
    rec = {k: None for k in D.ENVELOPE_KEYS}
    rec.update(ts=D.utc_iso(t), recv_ts=D.utc_iso(t + 0.05), env=env, boot_id="b1",
               source=source, source_id=sid(), event=event, data={})
    rec.update(kw)
    return rec


def hook(env, session, event, t, ses, claude_pid, hook_pid, parent_pid, claude_exe=GOOD_CLAUDE,
         loader_env=None, parent_exe="/usr/bin/dash", **ev):
    ancestry = [{"pid": hook_pid, "exe": "/usr/bin/python3.14", "start_time": 1},
                {"pid": parent_pid, "exe": parent_exe, "start_time": 1},
                {"pid": claude_pid, "exe": claude_exe, "start_time": 1},
                {"pid": 1, "exe": "/usr/lib/systemd/systemd", "start_time": 0}]
    observed = {"pid": hook_pid, "uid": 2000, "gid": 2000, "exe": "/usr/bin/python3.14",
                "cmdline": ["/usr/bin/python3", "-I", HOOK], "auid": 2000, "ses": ses,
                "ancestry": ancestry, "claude_pid": claude_pid, "claude_exe": claude_exe,
                "run_id": f"run-{session[:4]}", "loader_env": loader_env or {}}
    event_obj = dict({"hook_event_name": event, "session_id": session, "cwd": "/home/agent/p"}, **ev)
    return base(env, t, "hook", event, session_id=session, ses=ses, pid=hook_pid,
                run_id=f"run-{session[:4]}", uid=2000,
                data={"observed": observed, "event": event_obj})


def execrec(env, t, pid, ppid, ses, argv, exe):
    return base(env, t, "audit", "exec", ses=ses, pid=pid, uid=2000,
                data={"key": "agent-exec", "pid": pid, "ppid": ppid, "ses": ses, "argv": argv,
                      "exe": exe, "cwd": "/home/agent/p", "success": True})


def sh_exec(env, t, pid, claude_pid, ses):
    return execrec(env, t, pid, claude_pid, ses, ["/bin/sh", "-c", HOOK], "/usr/bin/dash")


def egress(t, client_env, decision, host="evil.example", env="host"):
    return base(env, t, "egress", "connect", client_env=client_env,
                data={"env": client_env, "method": "CONNECT", "host": host, "port": 443,
                      "decision": decision, "reason": "not-allowlisted" if decision == "deny" else None})


def build_store(root):
    """Three sessions:
    A host aaaa1111  ses 17 claude 100  clean, ended at T0+10
    B host bbbb2222  ses 17 claude 500  overlaps A; wrong binary, LD_PRELOAD,
                                        a forged hook, a tool without Post, no end
    C vm   cccc3333  ses 5  claude 700  no audit records; policy write and a quota report
    """
    tool = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "t1"}
    A = [sh_exec("host", T0 - 0.1, 200, 100, 17),
         hook("host", "aaaa1111", "SessionStart", T0, 17, 100, 300, 200, source="startup"),
         sh_exec("host", T0 + 0.9, 201, 100, 17),
         hook("host", "aaaa1111", "PreToolUse", T0 + 1, 17, 100, 301, 201, **tool),
         execrec("host", T0 + 1.5, 210, 100, 17,
                 ["/bin/bash", "-c", "source /home/agent/.claude/shell-snapshots/s.sh && eval ls"],
                 "/usr/bin/bash"),
         execrec("host", T0 + 1.6, 211, 210, 17, ["ls"], "/usr/bin/ls"),
         sh_exec("host", T0 + 2.9, 203, 100, 17),
         hook("host", "aaaa1111", "PostToolUse", T0 + 3, 17, 100, 303, 203, **tool),
         sh_exec("host", T0 + 9.9, 205, 100, 17),
         hook("host", "aaaa1111", "SessionEnd", T0 + 10, 17, 100, 305, 205, reason="exit")]
    B = [sh_exec("host", T0 + 1.9, 501, 500, 17),
         hook("host", "bbbb2222", "SessionStart", T0 + 2, 17, 500, 601, 501,
              claude_exe="/home/agent/.local/share/claude/versions/2/claude"),
         sh_exec("host", T0 + 2.9, 502, 500, 17),
         hook("host", "bbbb2222", "PreToolUse", T0 + 3, 17, 500, 602, 502,
              claude_exe="/home/agent/.local/share/claude/versions/2/claude",
              loader_env={"LD_PRELOAD": "/tmp/x.so"}, tool_name="Bash",
              tool_input={"command": "sleep 100"}, tool_use_id="t9"),
         execrec("host", T0 + 4, 510, 500, 17,
                 ["/bin/bash", "-c", "source /home/agent/.claude/shell-snapshots/s.sh && eval x"],
                 "/usr/bin/bash"),
         # The Bash tool shell exec's into sh and runs the hook itself.
         execrec("host", T0 + 4.5, 510, 500, 17, ["/bin/sh", "-c", HOOK], "/usr/bin/dash"),
         hook("host", "bbbb2222", "Stop", T0 + 5, 17, 500, 611, 510,
              claude_exe="/home/agent/.local/share/claude/versions/2/claude"),
         execrec("host", T0 + 5, 999, 998, 17, ["mystery"], "/usr/bin/mystery"),
         egress(T0 + 1.7, "host", "deny"),
         egress(T0 - 1, "host", "allow", host="api.anthropic.com"),
         egress(T0 + 6, "host", "deny", env="agent-vm1"),      # a VM's claim: ignored
         execrec("host", T0 + 500, 777, 1, 99, ["claude"], "/home/agent/bin/claude")]
    C = [hook("agent-vm1", "cccc3333", "SessionStart", T0 + 100, 5, 700, 801, 701),
         base("agent-vm1", T0 + 101, "audit", "policy", ses=5,
              data={"key": "agent-policy", "exe": "/usr/bin/vim",
                    "paths": [{"name": "/etc/claude-code/managed-settings.d/x.json"}]}),
         base("agent-vm1", T0 + 102, "meta", "quota-exceeded", data={"file": "x"}),
         egress(T0 + 103, "agent-vm1", "deny"),
         hook("agent-vm1", "cccc3333", "SessionEnd", T0 + 110, 5, 700, 802, 702)]
    for env in ("host", "agent-vm1"):
        os.makedirs(os.path.join(root, env))
    date = "2026-10-27"
    with open(os.path.join(root, "host", f"{date}.jsonl"), "w") as f:
        for rec in A + B + A:                  # A twice: at-least-once delivery
            f.write(json.dumps(rec) + "\n")
        f.write('{"truncated": ')               # a line still being written
    with open(os.path.join(root, "agent-vm1", f"{date}.jsonl"), "w") as f:
        for rec in C:
            f.write(json.dumps(rec) + "\n")
    return A, B, C


class AgentLogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import shutil
        import tempfile
        cls.root = tempfile.mkdtemp(prefix="agent-log-", dir=helpers.TMP_BASE)
        cls.addClassCleanup(shutil.rmtree, cls.root, True)
        cls.A, cls.B, cls.C = build_store(cls.root)
        cls.records = L.load(cls.root)
        cls.sessions = {s.session_id: s for s in L.build_sessions(cls.records)}

    def test_dedup(self):
        self.assertEqual(len(self.records), len(self.A) + len(self.B) + len(self.C))

    def test_sessions(self):
        self.assertEqual(sorted(self.sessions), ["aaaa1111", "bbbb2222", "cccc3333"])
        a = self.sessions["aaaa1111"].summary()
        self.assertEqual((a["env"], a["tools"], a["ended"], a["run_id"], a["ses"]),
                         ("host", 1, True, "run-aaaa", [17]))
        self.assertFalse(self.sessions["bbbb2222"].ended)

    def execs(self, s):
        return {(r["data"]["pid"], m) for r, m in self.sessions[s].execs}

    def test_exec_split_by_ppid_walk(self):
        a, b = self.execs("aaaa1111"), self.execs("bbbb2222")
        self.assertIn((211, "exact"), a)        # 211 -> 210 -> claude 100
        self.assertNotIn(211, {p for p, _ in b})
        self.assertIn((510, "exact"), b)
        self.assertIn((999, "ambiguous"), a)    # unknown parent while both are active
        self.assertIn((999, "ambiguous"), b)
        self.assertNotIn(777, {p for p, _ in a | b})   # other ses

    def test_net_correlation(self):
        a = {(r["data"]["host"], r["ts"], m) for r, m in self.sessions["aaaa1111"].net}
        b = {(r["data"]["host"], m) for r, m in self.sessions["bbbb2222"].net}
        self.assertIn(("api.anthropic.com", D.utc_iso(T0 - 1), "exact"), a)
        self.assertIn(("evil.example", D.utc_iso(T0 + 1.7), "probable"), a)
        self.assertIn(("evil.example", "probable"), b)
        self.assertEqual(len(b), 1)              # the VM's forged claim is ignored
        c = [(r["data"]["host"], m) for r, m in self.sessions["cccc3333"].net]
        self.assertEqual(c, [("evil.example", "exact")])

    def findings(self, s):
        return {f["check"]: f["level"] for f in L.verify_session(self.sessions[s], self.records)}

    def test_verify_clean_session(self):
        f = self.findings("aaaa1111")
        self.assertEqual(set(f.values()), {"ok"}, f)

    def test_verify_tampered_session(self):
        f = self.findings("bbbb2222")
        self.assertEqual(f["binary"], "FAIL")
        self.assertEqual(f["injection"], "FAIL")
        self.assertEqual(f["forged-hook"], "FAIL")
        self.assertEqual(f["completeness"], "WARN")
        self.assertEqual(f["origin"], "ok")      # the shape alone looks genuine

    def test_verify_without_audit(self):
        f = self.findings("cccc3333")
        self.assertEqual(f["hook-parent"], "WARN")  # unverifiable, not a pass
        self.assertEqual(f["policy"], "FAIL")
        self.assertEqual(f["pipeline"], "WARN")

    def test_policy_change_by_admin_is_warn(self):
        s = self.sessions["aaaa1111"]
        admin = base(s.env, s.start + 1, "audit", "policy", ses=99, auid=1000, uid=0,
                     data={"key": "agent-policy", "exe": "/usr/bin/install"})
        admin["_t"] = s.start + 1
        f = {x["check"]: x["level"] for x in L.verify_session(s, self.records + [admin])}
        self.assertEqual(f["policy"], "WARN")
        agent = dict(admin, ses=None, auid=2000)
        f = {x["check"]: x["level"] for x in L.verify_session(s, self.records + [agent])}
        self.assertEqual(f["policy"], "FAIL")

    def test_origin_shape(self):
        obs = hook("host", "s", "Stop", T0, 1, 10, 12, 11)["data"]["observed"]
        self.assertEqual(L.hook_shape_ok(obs), (True, ""))          # python3 <- dash <- claude
        bash = hook("host", "s", "Stop", T0, 1, 10, 12, 11, parent_exe="/usr/bin/bash")
        self.assertFalse(L.hook_shape_ok(bash["data"]["observed"])[0])
        direct = dict(obs, ancestry=[obs["ancestry"][0]] + obs["ancestry"][2:])
        self.assertFalse(L.hook_shape_ok(direct)[0])                # no sh in between
        fake = dict(obs, cmdline=["/usr/bin/python3", "/tmp/fake-hook"])
        self.assertFalse(L.hook_shape_ok(fake)[0])

    def test_parse_since(self):
        self.assertEqual(L.parse_since("2h", now=10000.0), 10000.0 - 7200)
        self.assertEqual(L.parse_since("1d", now=100000.0), 100000.0 - 86400)
        self.assertIsNotNone(L.parse_since("2026-10-27"))

    # --- the CLI as a program ------------------------------------------------

    def cli(self, *args):
        return subprocess.run([helpers.python(), "-I", helpers.program("agent-log"), *args,
                               "--store", self.root], capture_output=True, text=True, timeout=60)

    def test_cli_sessions(self):
        out = self.cli("sessions")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("aaaa1111", out.stdout)
        data = json.loads(self.cli("sessions", "--json", "--env", "agent-vm1").stdout)
        self.assertEqual([s["session_id"] for s in data], ["cccc3333"])

    def test_cli_timeline(self):
        out = self.cli("timeline", "aaaa", "--exec", "--net")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("PreToolUse", out.stdout)
        self.assertIn("ls", out.stdout)
        self.assertIn("[probable]", out.stdout)
        recs = json.loads(self.cli("timeline", "run-aaaa", "--all", "--json").stdout)
        self.assertEqual(recs, sorted(recs, key=lambda r: r["ts"]))
        self.assertTrue(any(r.get("match") == "ambiguous" for r in recs))
        self.assertNotEqual(self.cli("timeline", "zzzz").returncode, 0)

    def test_cli_net(self):
        out = json.loads(self.cli("net", "--denied", "--json").stdout)
        self.assertEqual(len(out), 2)            # host's two denies; the VM claim excluded
        out = json.loads(self.cli("net", "--env", "agent-vm1", "--json").stdout)
        self.assertEqual(len(out), 1)

    def test_cli_exec_tree(self):
        out = self.cli("exec", "aaaa1111")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("100 claude (session root)", out.stdout)
        self.assertIn("└─ 211 ls", out.stdout)

    def test_cli_verify(self):
        self.assertEqual(self.cli("verify", "aaaa1111").returncode, 0)
        out = self.cli("verify")
        self.assertEqual(out.returncode, 1)
        self.assertIn("unhooked-claude", out.stdout)
        report = json.loads(self.cli("verify", "--json").stdout)
        whole = report[-1]
        self.assertIsNone(whole["session"])
        self.assertIn(("unhooked-claude", "FAIL"),
                      {(f["check"], f["level"]) for f in whole["findings"]})

    def test_cli_tail_from_start(self):
        proc = subprocess.Popen([helpers.python(), "-I", helpers.program("agent-log"), "tail",
                                 "--from-start", "--store", self.root, "--env", "agent-vm1"],
                                stdout=subprocess.PIPE, text=True)
        try:
            line = proc.stdout.readline()
            self.assertIn("agent-vm1", line)
        finally:
            proc.kill()
            proc.wait()
            proc.stdout.close()


if __name__ == "__main__":
    unittest.main()
