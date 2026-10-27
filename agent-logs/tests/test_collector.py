"""Hook collector: SO_PEERCRED + /proc observation, spool, fsync before ack."""

import json
import os
import subprocess
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

S = helpers.load("agent-log-shipper")


def make_proc(root, pid, ppid, exe, cmdline, environ=None, start=1000, ses=17, auid=2000,
              comm="proc"):
    """A fake /proc/<pid> with the files observe_process() reads."""
    d = os.path.join(root, str(pid))
    os.makedirs(d)
    rest = ["S", str(ppid)] + ["0"] * 17 + [str(start), "0"]
    with open(os.path.join(d, "stat"), "w") as f:
        f.write(f"{pid} ({comm}) " + " ".join(rest) + "\n")
    os.symlink(exe, os.path.join(d, "exe"))
    with open(os.path.join(d, "cmdline"), "wb") as f:
        f.write(b"".join(a.encode() + b"\0" for a in cmdline))
    for name, value in (("loginuid", auid), ("sessionid", ses)):
        with open(os.path.join(d, name), "w") as f:
            f.write(str(value))
    with open(os.path.join(d, "cgroup"), "w") as f:
        f.write("0::/system.slice/agent-run-x.service\n")
    if environ is not None:
        with open(os.path.join(d, "environ"), "wb") as f:
            f.write(b"".join(f"{k}={v}".encode() + b"\0" for k, v in environ.items()))


class ObserveFixtureTest(unittest.TestCase):
    def setUp(self):
        self.proc = helpers.tempdir(self)
        make_proc(self.proc, 1, 0, "/usr/lib/systemd/systemd", ["/sbin/init"], {})
        make_proc(self.proc, 100, 1, "/opt/claude-code/2.1.300/claude",
                  ["claude", "--dangerously-skip-permissions"],
                  {"AGENT_RUN_ID": "20261027T180401-9c1e22aa", "HOME": "/home/agent"},
                  comm="weird) (name")
        make_proc(self.proc, 200, 100, "/usr/bin/dash", ["sh", "-c", "hook"], {})
        make_proc(self.proc, 300, 200, "/usr/bin/python3.14",
                  ["/usr/bin/python3", "-I", "/usr/local/lib/agent-audit/claude-audit-hook"],
                  {"LD_PRELOAD": "", "BASH_ENV": "/tmp/evil", "PATH": "/usr/bin"})

    def test_table_fields(self):
        obs = S.observe_process(300, 2000, 2000, self.proc)
        self.assertEqual(obs["pid"], 300)
        self.assertEqual((obs["uid"], obs["gid"]), (2000, 2000))
        self.assertEqual(obs["exe"], "/usr/bin/python3.14")
        self.assertEqual(obs["cmdline"][-1], "/usr/local/lib/agent-audit/claude-audit-hook")
        self.assertEqual((obs["auid"], obs["ses"]), (2000, 17))
        self.assertIn("agent-run-x.service", obs["cgroup"])
        self.assertEqual([a["pid"] for a in obs["ancestry"]], [300, 200, 100, 1])
        self.assertEqual(obs["ancestry"][2]["start_time"], 1000)
        # nearest non-shell ancestor; comm with parentheses parsed correctly
        self.assertEqual(obs["claude_pid"], 100)
        self.assertEqual(obs["claude_exe"], "/opt/claude-code/2.1.300/claude")
        self.assertEqual(obs["run_id"], "20261027T180401-9c1e22aa")
        # empty LD_PRELOAD (pinned by managed settings) is not reported
        self.assertEqual(obs["loader_env"], {"BASH_ENV": "/tmp/evil"})
        self.assertEqual(obs["errors"], [])

    def test_shell_list_is_configurable(self):
        self.assertIn("dash", S.SHELLS)
        old = S.SHELLS
        S.SHELLS = frozenset({"sh"})
        try:
            obs = S.observe_process(300, 2000, 2000, self.proc)
            self.assertEqual(obs["claude_pid"], 200)      # dash now counts as "claude"
        finally:
            S.SHELLS = old

    def test_unreadable_environ(self):
        os.unlink(os.path.join(self.proc, "300", "environ"))
        obs = S.observe_process(300, 2000, 2000, self.proc)
        self.assertIsNone(obs["loader_env"])
        self.assertTrue(any("loader_env" in e for e in obs["errors"]))

    def test_vanished_process(self):
        obs = S.observe_process(999, 2000, 2000, self.proc)
        self.assertIsNone(obs["exe"])
        self.assertEqual(obs["ancestry"], [])
        self.assertIsNone(obs["claude_pid"])


class SpoolTest(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.tempdir(self)
        self.state_path = os.path.join(self.dir, "state.json")

    def spool(self, **kw):
        state = S.State(self.state_path)
        return S.Spool(os.path.join(self.dir, "spool"), state, **kw)

    def test_segments_and_seq_never_reset(self):
        sp = self.spool(segment_size=300, cap=1 << 20)
        ids = [sp.write({"n": i, "pad": "x" * 100}) for i in range(6)]
        sp.sync()
        self.assertEqual(ids[0], "1:0")
        self.assertGreater(len(sp.segments()), 1)
        self.assertEqual(sp.segments()[-1], sp.seq)
        last_seq = sp.seq
        # Restart: continue in the newest segment.
        sp2 = self.spool(segment_size=300, cap=1 << 20)
        self.assertEqual(sp2.seq, last_seq)
        # Delete every segment: the counter still comes from state.json.
        for s in sp2.segments():
            os.unlink(sp2.path(s))
        sp3 = self.spool(segment_size=300, cap=1 << 20)
        sid = sp3.write({"n": "after"})
        self.assertEqual(int(sid.split(":")[0]), last_seq + 1)
        with open(self.state_path) as f:
            self.assertEqual(json.load(f)["hook_seq"], last_seq + 1)
        self.assertEqual(os.stat(self.state_path).st_mode & 0o777, 0o600)

    def test_torn_tail_dropped_on_restart(self):
        sp = self.spool()
        sp.write({"a": 1})
        sp.sync()
        with open(sp.path(sp.seq), "ab") as f:
            f.write(b'{"torn":')
        sp2 = self.spool()
        sid = sp2.write({"b": 2})
        sp2.sync()
        with open(sp2.path(sp2.seq), "rb") as f:
            lines = f.read().splitlines()
        self.assertEqual([json.loads(x) for x in lines], [{"a": 1}, {"b": 2}])
        self.assertEqual(sid, f"{sp2.seq}:{len(lines[0]) + 1}")

    def test_cap_in_forward_mode(self):
        sp = self.spool(segment_size=1000, cap=1500)
        sp.write({"pad": "x" * 900})
        with self.assertRaises(S.SpoolFull):
            sp.write({"pad": "y" * 900})

    def test_local_mode_prunes_at_90_percent(self):
        sp = self.spool(segment_size=400, cap=2000, local=True)
        for i in range(30):
            sp.write({"n": i, "pad": "z" * 150})
        sp.sync()
        self.assertLessEqual(sp.total, 2000)
        self.assertEqual(sp.total, sum(os.path.getsize(sp.path(s)) for s in sp.segments()))
        lines = []
        for s in sp.segments():
            lines += helpers.read_jsonl(sp.path(s))
        metas = [x["meta"] for x in lines if "meta" in x]
        self.assertTrue(metas and metas[0]["event"] == "spool-pruned")
        self.assertEqual(lines[-1]["n"], 29)          # newest record kept


class CollectorLiveTest(unittest.TestCase):
    """A real socket and real /proc: the hook is a child of this test runner."""

    CLIENT = r"""
import json, os, socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(float(sys.argv[3]))
s.connect(sys.argv[1])
body = sys.argv[2].encode()
s.sendall(struct.pack(">I", len(body)) + body)
try:
    reply = s.recv(2)
except socket.timeout:
    reply = b"TO"
print(json.dumps({"pid": os.getpid(), "reply": reply.decode()}))
"""

    def setUp(self):
        self.dir = helpers.tempdir(self)
        self.sock = os.path.join(helpers.sockdir(self), "hook.sock")
        self.fsyncs = []
        self.gate = threading.Event()
        self.gate.set()

        def spy_fsync(fd):
            self.gate.wait()
            self.fsyncs.append(fd)
            os.fsync(fd)

        state = S.State(os.path.join(self.dir, "state.json"))
        self.spool = S.Spool(os.path.join(self.dir, "spool"), state, fsync=spy_fsync)
        self.paths = []
        self.collector = S.Collector(self.sock, self.spool, "boot-x", on_paths=self.paths.extend,
                                     reply_timeout=5)
        self.collector.start()
        self.addCleanup(self.collector.sock.close)

    def spooled(self):
        out = []
        for s in self.spool.segments():
            out += helpers.read_jsonl(self.spool.path(s))
        return out

    def run_client(self, event, timeout=5.0, via_shell=True):
        cmd = [helpers.python(), "-c", self.CLIENT, self.sock, json.dumps(event), str(timeout)]
        if via_shell:
            # Keep sh alive as an intermediate ancestor (like `sh -c hook`).
            cmd = ["/bin/sh", "-c", '"$@"; true', "sh"] + cmd
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return json.loads(out.stdout)

    def test_socket_mode(self):
        self.assertEqual(os.stat(self.sock).st_mode & 0o777, 0o666)

    def test_observed_from_real_proc(self):
        event = {"hook_event_name": "PreToolUse", "session_id": "s1",
                 "transcript_path": "/home/agent/.claude/projects/p/s1.jsonl",
                 "audit": {"hook_ts": "2026-10-27T18:00:00.000Z"}}
        res = self.run_client(event)
        self.assertEqual(res["reply"], "ok")
        rec = self.spooled()[-1]
        self.assertEqual(rec["event"], event)
        self.assertEqual(rec["boot_id"], "boot-x")
        obs = rec["observed"]
        self.assertEqual(obs["pid"], res["pid"])
        self.assertEqual(obs["uid"], os.getuid())
        self.assertEqual(obs["gid"], os.getgid())
        self.assertEqual(os.path.realpath(obs["exe"]), os.path.realpath(sys.executable))
        pids = [a["pid"] for a in obs["ancestry"]]
        self.assertEqual(pids[0], res["pid"])
        self.assertIn(os.getpid(), pids)
        # sh is skipped; the nearest non-shell ancestor is this test runner.
        self.assertEqual(obs["claude_pid"], os.getpid())
        with open("/proc/self/sessionid") as f:
            self.assertEqual(obs["ses"], int(f.read()))
        self.assertEqual(self.paths, ["/home/agent/.claude/projects/p/s1.jsonl"])

    def test_no_ack_before_fsync(self):
        self.gate.clear()                 # fsync blocks until released
        result = {}
        t = threading.Thread(target=lambda: result.update(
            r=helpers.send_hook(self.sock, {"hook_event_name": "Stop"}, timeout=1.0)))
        t.start()
        t.join()
        self.assertEqual(result["r"], b"<timeout>")    # no ok while fsync pending
        self.assertEqual(self.fsyncs, [])
        self.gate.set()
        self.assertEqual(helpers.send_hook(self.sock, {"hook_event_name": "Stop"}), b"ok")
        self.assertTrue(self.fsyncs)

    def test_fsync_failure_means_no_ack(self):
        def broken(fd):
            raise OSError(5, "EIO")
        self.spool.fsync = broken
        self.assertEqual(helpers.send_hook(self.sock, {"hook_event_name": "Stop"}), b"")

    def test_spool_cap_means_no_ack(self):
        self.spool.cap = 6000              # the observed object alone is ~1-2 KiB
        self.assertEqual(helpers.send_hook(self.sock, {"x": "y" * 8000}), b"")
        self.assertEqual(helpers.send_hook(self.sock, {"x": 1}), b"ok")   # small one fits

    def test_bad_frames_get_no_ack(self):
        import socket
        import struct
        for payload in (struct.pack(">I", 0), struct.pack(">I", (1 << 20) + 1) + b"{}",
                        helpers.frame(b"not json"), helpers.frame(b"[1,2]")):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(self.sock)
            s.sendall(payload)
            try:
                reply = s.recv(2)
            except ConnectionResetError:      # closed with unread data: also "no ok"
                reply = b""
            self.assertEqual(reply, b"")
            s.close()
        self.assertEqual(self.spooled(), [])

    def test_max_frame_accepted(self):
        event = {"pad": "x" * ((1 << 20) - 20)}
        self.assertLessEqual(len(json.dumps(event)), 1 << 20)
        self.assertEqual(helpers.send_hook(self.sock, event), b"ok")

    def test_concurrent_hooks_do_not_interleave(self):
        replies = []
        threads = [threading.Thread(target=lambda i=i: replies.append(
            helpers.send_hook(self.sock, {"n": i, "pad": "p" * 5000}))) for i in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(replies, [b"ok"] * 24)
        recs = self.spooled()
        self.assertEqual(sorted(r["event"]["n"] for r in recs), list(range(24)))


if __name__ == "__main__":
    unittest.main()
