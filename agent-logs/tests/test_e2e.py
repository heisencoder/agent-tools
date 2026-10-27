"""End to end, as separate processes:

hook-style client -> agent-log-shipper (collector, spool, audit and
transcript sources, sender) -> agent-logd (unix socket, test mode) -> store
-> agent-log sessions / timeline / exec / verify.
"""

import json
import os
import pwd
import signal
import subprocess
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

CLIENT = r"""
import json, socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])
body = sys.argv[2].encode()
s.sendall(struct.pack(">I", len(body)) + body)
sys.stdout.write(s.recv(2).decode())
"""


def audit_exec_lines(t, serial, pid, ppid, ses, argv):
    stamp = f"{t:.3f}:{serial}"
    args = " ".join(f'a{i}="{a}"' for i, a in enumerate(argv))
    return [
        f'type=SYSCALL msg=audit({stamp}): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 '
        f'a2=3 a3=0 items=2 ppid={ppid} pid={pid} auid=2000 uid={os.getuid()} gid=2000 '
        f'euid=2000 ses={ses} comm="{argv[0]}" exe="/usr/bin/{argv[0]}" key="agent-exec"',
        f"type=EXECVE msg=audit({stamp}): argc={len(argv)} {args}",
        f'type=CWD msg=audit({stamp}): cwd="/home/agent/project"',
        f"type=EOE msg=audit({stamp}): ",
    ]


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.tempdir(self)
        socks = helpers.sockdir(self)
        self.store = os.path.join(self.dir, "store")
        os.makedirs(self.store)
        self.logd_sock = os.path.join(socks, "ingest.sock")
        self.hook_sock = os.path.join(socks, "hook.sock")
        self.runtime = os.path.join(self.dir, "run")
        self.state = os.path.join(self.dir, "state")
        self.audit_log = os.path.join(self.dir, "audit", "audit.log")
        os.makedirs(os.path.dirname(self.audit_log))
        open(self.audit_log, "w").close()
        self.auditd_conf = os.path.join(self.dir, "auditd.conf")
        with open(self.auditd_conf, "w") as f:
            f.write("admin_space_left = 1\n")
        self.transcripts = os.path.join(self.dir, "projects")
        os.makedirs(os.path.join(self.transcripts, "p"))
        self.transcript = os.path.join(self.transcripts, "p", "sess-e2e.jsonl")
        with open(self.transcript, "w") as f:
            f.write(json.dumps({"type": "user", "sessionId": "sess-e2e",
                                "timestamp": "2026-10-27T18:00:00.000Z"}) + "\n")
        with open("/proc/self/sessionid") as f:
            self.ses = int(f.read())
        self.logd = self.shipper = None
        self.start_logd()
        self.start_shipper()
        self.addCleanup(self.stop_all)

    def spawn(self, name, *args):
        proc = subprocess.Popen([helpers.python(), "-I", helpers.program(name), *args],
                                stdout=subprocess.DEVNULL,
                                stderr=None if helpers.VERBOSE else subprocess.DEVNULL)
        return proc

    def start_logd(self):
        self.logd = self.spawn("agent-logd", "--store", self.store, "--listen-unix",
                               self.logd_sock, "--allow-any-uid",
                               "--envs-conf", os.path.join(self.dir, "envs.conf"))
        self.assertTrue(helpers.wait_for(lambda: os.path.exists(self.logd_sock)))

    def start_shipper(self):
        if os.path.exists(self.hook_sock):
            os.unlink(self.hook_sock)
        self.shipper = self.spawn(
            "agent-log-shipper", "--mode", "host", "--hook-socket", self.hook_sock,
            "--runtime-dir", self.runtime, "--state-dir", self.state,
            "--logd-unix", self.logd_sock, "--audit-log", self.audit_log,
            "--auditd-conf", self.auditd_conf, "--journalctl", "",
            "--agent-user", pwd.getpwuid(os.getuid()).pw_name,
            "--transcripts-dir", self.transcripts,
            "--egress-user", "no-such-user-x", "--logd-user", "no-such-user-x")
        self.assertTrue(helpers.wait_for(lambda: os.path.exists(self.hook_sock)))

    def stop(self, proc):
        if proc and proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def stop_all(self):
        self.stop(self.shipper)
        self.stop(self.logd)

    def hook(self, event, **fields):
        ev = dict({"hook_event_name": event, "session_id": "sess-e2e", "cwd": "/home/agent/project",
                   "transcript_path": self.transcript,
                   "audit": {"hook_ts": "2026-10-27T18:00:00.000Z"}}, **fields)
        # sh stays as the intermediate parent, like Claude Code's `sh -c hook`.
        # Managed settings pin the loader variables empty for real hooks; CI
        # runners set some (setup-python exports LD_LIBRARY_PATH), so drop them.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("LD_") and k not in ("BASH_ENV", "ENV", "GCONV_PATH")}
        out = subprocess.run(["/bin/sh", "-c", '"$@"; true', "sh", helpers.python(), "-c",
                              CLIENT, self.hook_sock, json.dumps(ev)],
                             capture_output=True, text=True, timeout=30, env=env)
        return out.stdout

    def stored(self):
        recs = []
        for env in os.listdir(self.store):
            for name in os.listdir(os.path.join(self.store, env)):
                recs += helpers.read_jsonl(os.path.join(self.store, env, name))
        return recs

    def agent_log(self, *args):
        return subprocess.run([helpers.python(), "-I", helpers.program("agent-log"), *args,
                               "--store", self.store], capture_output=True, text=True, timeout=60)

    def test_pipeline(self):
        tool = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "tool_use_id": "tu1"}
        self.assertEqual(self.hook("SessionStart", source="startup"), "ok")
        self.assertEqual(self.hook("PreToolUse", **tool), "ok")
        now = time.time()
        with open(self.audit_log, "a") as f:
            f.write("\n".join(audit_exec_lines(now, 9001, 424242, os.getpid(), self.ses, ["ls", "-la"])
                              + audit_exec_lines(now, 9002, 434343, 1, self.ses + 1, ["other"]))
                    + "\n")
        self.assertEqual(self.hook("PostToolUse", **tool, tool_response={"stdout": "x"}), "ok")

        def arrived():
            recs = self.stored()
            kinds = [(r["source"], r["event"]) for r in recs]
            return (kinds.count(("hook", "PostToolUse")) and ("audit", "exec") in kinds
                    and ("transcript", "transcript") in kinds) and recs
        recs = helpers.wait_for(arrived, timeout=20)
        self.assertTrue(recs, "records did not reach the store")
        hook = next(r for r in recs if r["event"] == "PreToolUse")
        self.assertEqual(hook["env"], "host")
        self.assertEqual(hook["session_id"], "sess-e2e")
        self.assertEqual(hook["ses"], self.ses)
        self.assertEqual(hook["data"]["observed"]["claude_pid"], os.getpid())
        self.assertRegex(hook["source_id"], r"^1:\d+$")
        self.assertIsNotNone(hook["recv_ts"])
        self.assertFalse(os.path.exists(os.path.join(self.runtime, "audit-degraded")))
        state = json.load(open(os.path.join(self.state, "state.json")))
        self.assertIn("hook", state["cursors"])

        # agent-logd goes away: hooks are still acked (spooled) and delivered later.
        self.stop(self.logd)
        self.assertEqual(self.hook("SessionEnd", reason="exit"), "ok")
        time.sleep(1.5)
        self.assertFalse(any(r["event"] == "SessionEnd" for r in self.stored()))
        self.start_logd()
        self.assertTrue(helpers.wait_for(
            lambda: any(r["event"] == "SessionEnd" for r in self.stored()), timeout=30))

        # Restart the shipper: it resumes from its acked cursors.
        self.stop(self.shipper)
        self.start_shipper()
        self.assertEqual(self.hook("Stop"), "ok")
        self.assertTrue(helpers.wait_for(
            lambda: any(r["event"] == "Stop" for r in self.stored()), timeout=20))

        sessions = json.loads(self.agent_log("sessions", "--json").stdout)
        self.assertEqual(len(sessions), 1)
        s = sessions[0]
        self.assertEqual((s["session_id"], s["env"], s["tools"]), ("sess-e2e", "host", 1))
        self.assertEqual(s["execs"], 1)          # the other ses is not this session's

        timeline = json.loads(self.agent_log("timeline", "sess-e2e", "--all", "--json").stdout)
        events = [r["event"] for r in timeline if r["source"] == "hook"]
        self.assertEqual(events, ["SessionStart", "PreToolUse", "PostToolUse", "SessionEnd", "Stop"])
        self.assertIn("transcript", {r["source"] for r in timeline})
        execs = [r for r in timeline if r["source"] == "audit"]
        self.assertEqual(execs[0]["data"]["argv"], ["ls", "-la"])

        tree = self.agent_log("exec", "sess-e2e")
        self.assertIn("424242 ls -la", tree.stdout)

        verify = self.agent_log("verify", "sess-e2e", "--json")
        report = {f["check"]: f["level"] for f in json.loads(verify.stdout)[0]["findings"]}
        # The test "claude" is the Python test runner, not /opt/claude-code.
        self.assertEqual(report["binary"], "FAIL")
        self.assertEqual(verify.returncode, 1)
        self.assertEqual(report["injection"], "ok")
        self.assertEqual(report["pipeline"], "ok")


if __name__ == "__main__":
    unittest.main()
