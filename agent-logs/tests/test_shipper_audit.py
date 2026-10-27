"""auditd tailing: grouping, decoding, truncation, source_id, rotation, resume."""

import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

S = helpers.load("agent-log-shipper")
FIXTURE = os.path.join(helpers.FIXTURES, "audit-sample.txt")


def fixture_lines():
    with open(FIXTURE, encoding="utf-8") as f:
        return f.read().splitlines()


def group(serial):
    return [ln for ln in fixture_lines() if f":{serial}):" in ln]


class ParseTest(unittest.TestCase):
    def test_exec_with_hex_argument(self):
        event, d = S.build_audit_event(group(501))
        self.assertEqual(event, "exec")
        self.assertEqual(d["argv"], ["bash", "-c", "ls -la /tmp/a b"])
        self.assertEqual(d["cwd"], "/home/agent/project")
        self.assertEqual((d["pid"], d["ppid"], d["auid"], d["ses"], d["uid"]),
                         (4200, 4100, 2000, 17, 2000))
        self.assertEqual(d["exe"], "/usr/bin/bash")
        self.assertIs(d["success"], True)
        self.assertEqual(d["key"], "agent-exec")
        self.assertEqual(len(d["paths"]), 2)
        self.assertEqual(d["proctitle"], "bash -c ls -la /tmp/a b")
        self.assertEqual(d["types"], ["SYSCALL", "EXECVE", "CWD", "PATH", "PATH", "PROCTITLE", "EOE"])

    def test_enriched_format_and_hex_cwd(self):
        _, d = S.build_audit_event(group(502))
        self.assertEqual(d["argv"], ["ls", "-la", "/tmp/a b"])
        self.assertEqual(d["cwd"], "/home/agent/my project")
        self.assertEqual(d["key"], "agent-exec")       # not polluted by the \x1d suffix

    def test_failed_exec(self):
        _, d = S.build_audit_event(group(503))
        self.assertIs(d["success"], False)
        self.assertEqual(d["exit"], -2)

    def test_split_argument(self):
        _, d = S.build_audit_event(group(508))
        self.assertEqual(d["argv"], ["echo", "A" * 10 + "B" * 10])

    def test_multi_key_hex(self):
        event, d = S.build_audit_event(group(509))
        self.assertEqual((event, d["key"]), ("exec", "agent-exec"))

    def test_filtering(self):
        self.assertIsNone(S.build_audit_event(group(504)))     # key=(null)
        event, d = S.build_audit_event(group(505))
        self.assertEqual(event, "netfilter-cfg")
        nf = d["records"][0]
        self.assertEqual((nf["type"], nf["table"], nf["op"]),
                         ("NETFILTER_CFG", "agent_egress:12", "nft_unregister_table"))
        self.assertEqual(S.build_audit_event(group(506))[0], "exec")   # key agent-exec on CONFIG_CHANGE
        self.assertEqual(S.build_audit_event(group(507))[0], "secret-read")

    def test_config_change_without_our_key(self):
        line = ('type=CONFIG_CHANGE msg=audit(1793136009.000:900): auid=1000 ses=3 '
                'op=add_rule key=(null) list=4 res=1')
        self.assertEqual(S.build_audit_event([line])[0], "config-change")

    def test_argument_truncation(self):
        big = "x" * (20 << 10)
        out, trunc = S.truncate_args(["cmd", big])
        self.assertEqual(len(out[1]), 16 << 10)
        self.assertEqual(trunc["1"]["length"], 20 << 10)
        self.assertEqual(len(trunc["1"]["sha256"]), 64)
        many = ["y" * (15 << 10)] * 40                  # 600 KiB in total
        out, trunc = S.truncate_args(many)
        self.assertEqual(sum(len(a) for a in out), 512 << 10)
        self.assertNotIn("33", trunc)                   # 34th arg still fits whole
        self.assertIn("34", trunc)
        self.assertEqual(out[-1], "")


class GrouperTest(unittest.TestCase):
    def test_eoe_interleave_idle_and_flush(self):
        g = S.AuditGrouper(idle=2.0)
        done = []
        for i, line in enumerate(fixture_lines()):
            done += g.feed(line, i * 100, now=0.0)
        serials = [k[1] for k, _ in done]
        # 503 is shorter, so its EOE arrives first in the interleave
        self.assertEqual(serials, ["501", "503", "502", "504", "505", "507", "508", "509"])
        self.assertEqual(list(g.pending), [("1793136000.500", "506")])   # no EOE
        self.assertEqual(g.min_offset(10_000), g.pending[("1793136000.500", "506")]["first"])
        self.assertEqual(g.expire(1.0), [])
        self.assertEqual([k[1] for k, _ in g.expire(2.5)], ["506"])


class TailTest(unittest.TestCase):
    def setUp(self):
        self.dir = helpers.tempdir(self)
        self.log = os.path.join(self.dir, "audit.log")
        self.state = S.State(os.path.join(self.dir, "state.json"))

    def source(self, **kw):
        src = S.AuditSource(self.state, self.log, "boot-now", btime=1793135000,
                            poll=0.02, idle=0.2, **kw)
        src.start()
        return src

    def test_tail_fixture(self):
        shutil.copy(FIXTURE, self.log)
        src = self.source()
        got = helpers.drain(src.queue, 8)          # 504 is filtered out
        recs = [r for r, _ in got]
        self.assertEqual(len(recs), 8)
        ids = [r["source_id"] for r in recs]
        self.assertEqual(ids[0], "boot-now:1793136000.100:501")
        self.assertEqual(len(set(ids)), 8)
        self.assertIn("boot-now:1793136000.500:506", ids)       # completed by idle timeout
        first = recs[0]
        self.assertEqual((first["source"], first["event"], first["ses"], first["pid"]),
                         ("audit", "exec", 17, 4200))
        self.assertEqual(first["ts"], S.utc_iso(1793136000.1))
        # cursors carry the inode and never pass an incomplete group
        cursors = [c for _, c in got]
        self.assertTrue(all(c["inode"] == os.stat(self.log).st_ino for c in cursors))
        self.assertEqual(cursors[-1]["offset"], os.path.getsize(self.log))

    def test_rotation_and_resume(self):
        lines = fixture_lines()
        first_half = [ln for ln in lines if ":501)" in ln or ":502)" in ln or ":503)" in ln]
        second = [ln for ln in lines if ":507)" in ln or ":508)" in ln]
        with open(self.log, "w") as f:
            f.write("\n".join(first_half) + "\n")
        src = self.source()
        got = helpers.drain(src.queue, 3)
        self.assertEqual([r["source_id"].split(":")[-1] for r, _ in got], ["501", "503", "502"])
        # Rotate: an unfinished group sits at the end of the old file.
        with open(self.log, "a") as f:
            f.write(group(509)[0] + "\n")               # SYSCALL of 509, no EOE yet
        os.rename(self.log, self.log + ".1")
        with open(self.log, "w") as f:
            f.write("\n".join(second) + "\n")
        more = helpers.drain(src.queue, 3)
        self.assertEqual([r["source_id"].split(":")[-1] for r, _ in more], ["509", "507", "508"])
        self.assertTrue(src.queue.empty())
        # Commit as the sender would after an ack, then restart: no re-reads.
        for _, cursor in got + more:
            src.apply_commit(cursor)
        self.state.update(cursors={"audit": src.committed()})
        with open(self.log, "a") as f:
            f.write("\n".join(group(501)).replace(":501)", ":601)") + "\n")
        src2 = self.source()
        again = helpers.drain(src2.queue, 1, timeout=3)
        self.assertEqual([r["source_id"].split(":")[-1] for r, _ in again], ["601"])
        self.assertEqual(helpers.drain(src2.queue, 1, timeout=0.5), [])

    def test_resume_from_rotated_cursor(self):
        """A restart whose cursor points into audit.log.1 finishes it first."""
        lines = fixture_lines()
        with open(self.log + ".1", "w") as f:
            f.write("\n".join(group(501) + group(507)) + "\n")
        with open(self.log, "w") as f:
            f.write("\n".join(group(508)) + "\n")
        offset = len("\n".join(group(501))) + 1
        self.state.update(cursors={"audit": {"inode": os.stat(self.log + ".1").st_ino,
                                             "offset": offset, "boot_id": "boot-now"}})
        src = self.source()
        got = helpers.drain(src.queue, 2)
        self.assertEqual([r["source_id"].split(":")[-1] for r, _ in got], ["507", "508"])
        self.assertTrue(lines)

    def test_previous_boot_id_for_old_lines(self):
        self.state.update(cursors={"audit": {"inode": -1, "offset": 0, "boot_id": "boot-old"}})
        src = S.AuditSource(self.state, self.log, "boot-now", btime=1793136000.5)
        self.assertEqual(src.boot_id_for(1793136000.1), "boot-old")
        self.assertEqual(src.boot_id_for(1793136001.0), "boot-now")
        rec = src.record_for(("1793136000.100", "501"), {"lines": group(501)})
        self.assertEqual(rec["source_id"], "boot-old:1793136000.100:501")
        self.assertEqual(rec["boot_id"], "boot-old")


if __name__ == "__main__":
    unittest.main()
