"""Shipper sources: transcripts (safe reads), journald, hook spool reader,
sender batching/acks/cursor commits, and the audit-degraded flag."""

import json
import os
import socket
import sys
import threading
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

S = helpers.load("agent-log-shipper")
JOURNAL = os.path.join(helpers.FIXTURES, "journal-sample.jsonl")


def collect(src):
    out = []
    while not src.queue.empty():
        out.append(src.queue.get_nowait())
    return out


class TranscriptTest(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.tempdir(self)
        self.root = os.path.join(self.dir, "projects")
        self.proj = os.path.join(self.root, "-home-agent-proj")
        os.makedirs(self.proj)
        self.state = S.State(os.path.join(self.dir, "state.json"))

    def src(self, uid=None):
        return S.TranscriptSource(self.state, [self.root], os.getuid() if uid is None else uid,
                                  "boot-x")

    def write(self, name, data, mode="ab"):
        path = os.path.join(self.proj, name)
        with open(path, mode) as f:
            f.write(data)
        return path

    def test_complete_lines_only(self):
        line = {"type": "user", "sessionId": "s1", "timestamp": "2026-10-27T18:00:00.000Z"}
        path = self.write("s1.jsonl", (json.dumps(line) + "\n").encode() + b'{"type": "assi')
        src = self.src()
        src.poll_once()
        got = collect(src)
        self.assertEqual(len(got), 1)
        rec, cursor = got[0]
        self.assertEqual((rec["source"], rec["event"], rec["session_id"]),
                         ("transcript", "transcript", "s1"))
        self.assertTrue(rec["data"]["claim"])
        self.assertEqual(rec["source_id"], f"{path}:{os.stat(path).st_ino}:0")
        self.assertEqual(rec["ts"], "2026-10-27T18:00:00.000Z")
        self.write("s1.jsonl", b'stant"}\n')
        src.poll_once()
        got2 = collect(src)
        self.assertEqual(got2[0][0]["data"]["line"], {"type": "assistant"})
        self.assertEqual(got2[0][1][2], os.path.getsize(path))

    def test_symlink_fifo_wrong_owner_and_symlinked_dir(self):
        outside = os.path.join(self.dir, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "secret.jsonl"), "w") as f:
            f.write('{"secret": 1}\n')
        os.symlink(os.path.join(outside, "secret.jsonl"), os.path.join(self.proj, "link.jsonl"))
        os.symlink(outside, os.path.join(self.proj, "dirlink"))
        os.mkfifo(os.path.join(self.proj, "fifo.jsonl"))
        src = self.src()
        src.poll_once()                         # must not hang on the FIFO
        self.assertEqual(collect(src), [])
        self.write("mine.jsonl", b'{"ok": 1}\n')
        src.poll_once()
        self.assertEqual(len(collect(src)), 1)
        other = self.src(uid=os.getuid() + 12345)  # files now have the "wrong" owner
        other.poll_once()
        self.assertEqual(collect(other), [])

    def test_oversized_line(self):
        big = b'{"pad": "' + b"x" * (1536 << 10) + b'"}'
        path = self.write("big.jsonl", big + b"\n" + b'{"after": 1}\n')
        src = self.src()
        for _ in range(3):
            src.poll_once()
        got = collect(src)
        self.assertEqual([r["event"] for r, _ in got], ["transcript-oversize", "transcript"])
        stub = got[0][0]["data"]
        self.assertEqual(stub["length"], len(big))
        import hashlib
        self.assertEqual(stub["sha256"], hashlib.sha256(big).hexdigest())
        self.assertEqual(got[0][0]["source_id"], f"{path}:{os.stat(path).st_ino}:0")
        self.assertEqual(got[1][0]["data"]["line"], {"after": 1})

    def test_shrink_and_inode_change(self):
        path = self.write("s.jsonl", b'{"a": 1}\n{"b": 2}\n')
        src = self.src()
        src.poll_once()
        self.assertEqual(len(collect(src)), 2)
        with open(path, "wb") as f:              # shrink in place
            f.write(b'{"c": 3}\n')
        src.poll_once()
        got = collect(src)
        self.assertEqual([r["event"] for r, _ in got], ["transcript-rewritten", "transcript"])
        self.assertEqual(got[0][0]["source"], "meta")
        self.assertEqual(got[0][0]["data"]["old_offset"], 18)
        tmp = path + ".new"                       # replace the file (new inode)
        with open(tmp, "wb") as f:
            f.write(b'{"c": 3}\n{"d": 4}\n')
        os.replace(tmp, path)
        src.poll_once()
        got = collect(src)
        self.assertEqual([r["event"] for r, _ in got],
                         ["transcript-rewritten", "transcript", "transcript"])

    def test_hook_paths_and_resume(self):
        elsewhere = os.path.join(self.dir, "other", "agent.jsonl")
        os.makedirs(os.path.dirname(elsewhere))
        with open(elsewhere, "w") as f:
            f.write('{"x": 1}\n')
        src = self.src()
        src.add_paths([elsewhere, "relative/ignored.jsonl"])
        src.poll_once()
        got = collect(src)
        self.assertEqual(len(got), 1)
        src.apply_commit(got[0][1])
        self.state.update(cursors={"transcript": src.committed()})
        with open(elsewhere, "a") as f:
            f.write('{"x": 2}\n')
        src2 = self.src()                         # restart: tracked path remembered
        src2.poll_once()
        got2 = collect(src2)
        self.assertEqual([r["data"]["line"] for r, _ in got2], [{"x": 2}])


class JournalTest(unittest.TestCase):
    ENV_BY_IP = {"192.168.123.10": "agent-vm1"}

    def entries(self):
        return helpers.read_jsonl(JOURNAL)

    def classify(self):
        return [S.classify_journal(e, 990, 991, self.ENV_BY_IP) for e in self.entries()]

    def test_classification(self):
        out = self.classify()
        kinds = [(r["source"], r["event"]) if r else None for r in out]
        self.assertEqual(kinds, [
            ("egress", "connect"),
            None,                                 # forged: wrong _UID
            ("meta", "proxy-log"),                # plain-text proxy line
            ("netfilter", "drop"),
            ("netfilter", "drop"),
            None,                                 # unrelated kernel message
            ("meta", "journal-suppressed"),
            ("meta", "pipeline-log"),
            ("netfilter", "drop"),                # MESSAGE as a byte array
            ("meta", "pipeline-log"),
        ])
        egress = out[0]
        self.assertEqual(egress["client_env"], "agent-vm1")
        self.assertEqual(egress["ts"], "2026-10-27T18:00:00.050Z")   # proxy's own ts
        self.assertEqual(egress["data"]["reason"], "not-allowlisted")
        self.assertEqual(egress["source_id"], self.entries()[0]["__CURSOR"])
        self.assertEqual(egress["uid"], 990)
        host_drop, vm_drop = out[3], out[4]
        self.assertEqual((host_drop["client_env"], host_drop["uid"]), ("host", 2000))
        self.assertEqual(host_drop["data"]["fields"]["dpt"], "443")
        self.assertEqual(vm_drop["client_env"], "agent-vm1")
        self.assertEqual(vm_drop["data"]["prefix"], "agent-vmnet-drop")
        self.assertEqual(out[8]["data"]["prefix"], "agent-vmnet-fwd-drop")
        self.assertEqual(out[7]["data"]["priority"], 3)

    def test_without_egress_user(self):
        out = [S.classify_journal(e, None, None, {}) for e in self.entries()]
        self.assertIsNone(out[0])                 # no agent-egress user: never trusted
        self.assertIsNone(out[9])

    def test_journalctl_args(self):
        args = S.journalctl_args("journalctl", None, 990, 991)
        self.assertEqual(args[:6], ["journalctl", "--all", "-o", "json", "--follow", "--no-pager"])
        self.assertIn("--boot", args)
        groups, cur = [], []
        for a in args[7:]:
            if a == "+":
                groups.append(cur)
                cur = []
            else:
                cur.append(a)
        groups.append(cur)
        self.assertEqual(groups, [
            ["_SYSTEMD_UNIT=agent-egress-proxy.service", "_UID=990"],
            ["_TRANSPORT=kernel"],
            ["MESSAGE_ID=a596d6fe7bfa4994828e72309e95d61e"],
            ["_SYSTEMD_UNIT=agent-log-shipper.service", "_UID=0"],
            ["_SYSTEMD_UNIT=agent-logd.service", "_UID=991"]])
        args = S.journalctl_args("journalctl", "s=abc;i=5", None, None)
        self.assertIn("--after-cursor=s=abc;i=5", args)
        self.assertNotIn("_UID=990", args)

    def test_subprocess_and_resume_from_cursor(self):
        d = helpers.tempdir(self)
        argv_log = os.path.join(d, "argv.json")
        fake = os.path.join(d, "journalctl")
        with open(fake, "w") as f:
            f.write(f"#!{helpers.python()}\nimport json, sys\n"
                    f"open({argv_log!r}, 'a').write(json.dumps(sys.argv) + '\\n')\n"
                    f"sys.stdout.write(open({JOURNAL!r}).read())\n")
        os.chmod(fake, 0o755)
        envs = os.path.join(d, "envs.conf")
        with open(envs, "w") as f:
            f.write("agent-vm1 cid=10 ip=192.168.123.10 mac=52:54:00:a9:00:10\n")
        state = S.State(os.path.join(d, "state.json"))
        src = S.JournalSource(state, fake, 990, 991, envs)
        with self.assertRaises(RuntimeError):     # fake journalctl exits after the fixture
            src.run()
        got = collect(src)
        self.assertEqual(len(got), 8)
        self.assertEqual(got[2][0]["client_env"], "host")      # host drop
        # Ack the first three, persist, restart: resume after the acked cursor.
        for _, cursor in got[:3]:
            src.apply_commit(cursor)
        state.update(cursors={"journal": src.committed()})
        src2 = S.JournalSource(S.State(os.path.join(d, "state.json")), fake, 990, 991, envs)
        with self.assertRaises(RuntimeError):
            src2.run()
        argvs = helpers.read_jsonl(argv_log)
        self.assertIn("--boot", argvs[0])
        self.assertIn(f"--after-cursor={got[2][1]}", argvs[1])


class HookSpoolSourceTest(unittest.TestCase):
    def test_reads_across_segments_and_deletes_acked(self):
        d = helpers.tempdir(self)
        state = S.State(os.path.join(d, "state.json"))
        spool = S.Spool(os.path.join(d, "spool"), state, segment_size=600)
        for i in range(6):
            spool.write({"ts": "t", "boot_id": "b", "observed": {"pid": i, "ses": 3},
                         "event": {"hook_event_name": "PreToolUse", "session_id": "s", "n": i,
                                   "pad": "x" * 150}})
        spool.write({"ts": "t", "boot_id": "b", "meta": {"event": "audit-degraded"}})
        spool.sync()
        wake = threading.Event()
        src = S.HookSpoolSource(state, spool, wake)
        src.start()
        got = helpers.drain(src.queue, 7)
        recs = [r for r, _ in got]
        self.assertEqual([r["event"] for r in recs], ["PreToolUse"] * 6 + ["audit-degraded"])
        self.assertEqual([r["data"]["event"].get("n") for r in recs[:6]], list(range(6)))
        self.assertEqual(recs[-1]["source"], "meta")
        self.assertEqual(recs[0]["source_id"], "1:0")
        self.assertEqual(recs[0]["ses"], 3)
        self.assertEqual(len({r["source_id"] for r in recs}), 7)
        before = spool.segments()
        self.assertGreater(len(before), 2)
        for _, c in got:
            src.apply_commit(c)
        src.after_commit()
        self.assertEqual(spool.segments(), [got[-1][1][0]])


class FakeSource(S.Source):
    def __init__(self, state, name):
        self.name = name
        super().__init__(state)


class SenderTest(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.tempdir(self)
        self.state = S.State(os.path.join(self.dir, "state.json"))
        self.a, self.b = FakeSource(self.state, "a"), FakeSource(self.state, "b")
        for i in range(3):
            self.a.put({"source": "meta", "source_id": f"a{i}"}, i)
            self.b.put({"source": "meta", "source_id": f"b{i}"}, 10 + i)

    def server(self, behaviours):
        """A fake agent-logd; behaviours[i] for the i-th batch: 'ack' or 'close'."""
        path = os.path.join(helpers.sockdir(self), "logd.sock")
        lsock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        lsock.bind(path)
        lsock.listen(4)
        self.addCleanup(lsock.close)
        received = []

        def serve():
            for behaviour in behaviours:
                conn, _ = lsock.accept()
                f = conn.makefile("rb")
                lines = []
                for raw in f:
                    obj = json.loads(raw)
                    if list(obj) == ["batch"]:
                        if behaviour == "ack":
                            received.append(lines)
                            conn.sendall(json.dumps({"ack": obj["batch"]}).encode() + b"\n")
                        break
                    lines.append(obj)
                f.close()
                conn.close()

        threading.Thread(target=serve, daemon=True).start()
        return path, received

    def test_commit_only_after_ack(self):
        path, received = self.server(["close", "ack"])
        sender = S.Sender([self.a, self.b], self.state, lambda: S.connect_unix(path))
        batch = sender.collect(wait=0.1)
        self.assertEqual(len(batch), 6)
        self.assertEqual([json.loads(line)["source_id"] for _, line, _ in batch],
                         ["a0", "b0", "a1", "b1", "a2", "b2"])     # round-robin
        with self.assertRaises(S.ProtocolError):
            sender.send_batch(batch)
        self.assertEqual(self.state.get("cursors"), None)        # nothing committed
        sender.sock.close()
        sender.sock = None
        sender.send_batch(batch)
        sender.commit(batch)
        self.assertEqual(self.state.get("cursors"), {"a": 2, "b": 12})
        self.assertEqual(len(received[0]), 6)
        with open(os.path.join(self.dir, "state.json")) as f:
            self.assertEqual(json.load(f)["cursors"], {"a": 2, "b": 12})

    def test_run_retries_until_acked(self):
        path, received = self.server(["close", "ack"])
        sender = S.Sender([self.a, self.b], self.state, lambda: S.connect_unix(path),
                          max_backoff=0.05)
        sender.start()
        self.assertTrue(helpers.wait_for(lambda: self.state.get("cursors")))
        self.assertEqual(self.state.get("cursors"), {"a": 2, "b": 12})


class AuditHealthTest(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.tempdir(self)
        self.conf = os.path.join(self.dir, "auditd.conf")
        self.flag = os.path.join(self.dir, "audit-degraded")
        self.events = []
        self.free = 100 << 20

    def health(self, conf_text):
        with open(self.conf, "w") as f:
            f.write(conf_text)

        def statvfs(path):
            return SimpleNamespace(f_bavail=self.free // 4096, f_frsize=4096,
                                   f_blocks=(1000 << 20) // 4096)
        return S.AuditHealth(self.conf, self.dir, self.flag,
                             lambda ev, **kw: self.events.append(ev), statvfs=statvfs)

    def test_threshold_in_megabytes(self):
        h = self.health("space_left = 75\nadmin_space_left = 50 # MB\n")
        self.assertFalse(h.check_once()["degraded"])
        self.assertFalse(os.path.exists(self.flag))
        self.free = 10 << 20
        self.assertTrue(h.check_once()["degraded"])
        self.assertTrue(os.path.exists(self.flag))
        with open(self.flag) as f:
            self.assertIn("admin_space_left", json.load(f)["reason"])
        h.check_once()                           # still degraded: no second event
        self.free = 60 << 20
        self.assertFalse(h.check_once()["degraded"])
        self.assertFalse(os.path.exists(self.flag))
        self.assertEqual(self.events, ["audit-degraded", "audit-recovered"])

    def test_percentage_and_missing_conf(self):
        h = self.health("admin_space_left = 20%\n")     # 20% of 1000 MiB = 200 MiB
        self.assertTrue(h.check_once()["degraded"])
        os.unlink(self.conf)
        h2 = S.AuditHealth(self.conf, self.dir, self.flag, lambda *a, **k: None)
        status = h2.check_once()
        self.assertTrue(status["degraded"])          # fail closed
        self.assertIn("cannot read", status["reason"])


class EnvsConfTest(unittest.TestCase):
    def test_example_file(self):
        envs = S.parse_envs_conf(os.path.join(helpers.REPO, "envs.conf.example"))
        self.assertEqual(envs, [{"name": "agent-vm1", "cid": 10, "ip": "192.168.123.10",
                                 "mac": "52:54:00:a9:00:10"}])

    def test_bad_lines(self):
        d = helpers.tempdir(self)
        for text in ("host cid=3\n", "Bad cid=3\n", "vm cid3\n"):
            path = os.path.join(d, "envs.conf")
            with open(path, "w") as f:
                f.write(text)
            with self.assertRaises(ValueError):
                S.parse_envs_conf(path)
        self.assertEqual(S.parse_envs_conf(os.path.join(d, "missing")), [])


if __name__ == "__main__":
    unittest.main()
