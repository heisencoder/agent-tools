"""Tests for claude-audit-hook: truncation, stubbing, framing, exit codes."""

import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auditsupport as S  # noqa: E402

hook = S.load_hook()
KIB = 1024
MIB = 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def decode_frame(frame):
    (length,) = struct.unpack(">I", frame[:4])
    body = frame[4:]
    assert length == len(body), (length, len(body))
    return json.loads(body.decode("utf-8"))


def base_event(**extra):
    event = {
        "session_id": "4b1f0000-0000-0000-0000-000000000000",
        "transcript_path": "/home/agent/.claude/projects/p/s.jsonl",
        "cwd": "/home/agent/work",
        "permission_mode": "bypassPermissions",
        "hook_event_name": "PreToolUse",
        "tool_name": "Write",
        "tool_use_id": "toolu_01",
    }
    event.update(extra)
    return event


class TruncationTests(unittest.TestCase):

    def test_small_event_unchanged(self):
        event = base_event(tool_input={"file_path": "/x", "content": "hi"})
        rec = decode_frame(hook.build_record(event, hook_ts="2026-10-27T18:04:11.532Z"))
        audit = rec.pop("audit")
        self.assertEqual(rec, event)
        self.assertEqual(audit, {"hook_ts": "2026-10-27T18:04:11.532Z"})
        self.assertNotIn("truncated", audit)

    def test_hook_ts_format(self):
        rec = decode_frame(hook.build_record(base_event()))
        self.assertRegex(rec["audit"]["hook_ts"],
                         r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")

    def test_nested_string_truncated_with_pointer(self):
        long = "x" * (20 * KIB)
        event = base_event(tool_name="MultiEdit", tool_input={
            "file_path": "/a",
            "edits": [{"old_string": "a", "new_string": long}],
        })
        rec = decode_frame(hook.build_record(event))
        new = rec["tool_input"]["edits"][0]["new_string"]
        self.assertEqual(new, long[:16 * KIB])
        self.assertEqual(rec["audit"]["truncated"], {
            "/tool_input/edits/0/new_string": {
                "length": 20 * KIB, "sha256": sha(long.encode())}})
        self.assertEqual(rec["tool_input"]["edits"][0]["old_string"], "a")

    def test_exactly_16k_not_truncated(self):
        s = "y" * (16 * KIB)
        rec = decode_frame(hook.build_record(base_event(tool_input={"c": s})))
        self.assertEqual(rec["tool_input"]["c"], s)
        self.assertNotIn("truncated", rec["audit"])

    def test_multibyte_cut_on_character_boundary(self):
        s = "é" * (10 * KIB)              # 2 bytes each: 20 KiB of UTF-8
        rec = decode_frame(hook.build_record(base_event(tool_input={"c": s})))
        out = rec["tool_input"]["c"]
        self.assertLessEqual(len(out.encode()), 16 * KIB)
        self.assertTrue(s.startswith(out))
        self.assertEqual(len(out), 8 * KIB)
        info = rec["audit"]["truncated"]["/tool_input/c"]
        self.assertEqual(info["length"], 20 * KIB)
        self.assertEqual(info["sha256"], sha(s.encode()))

    def test_pointer_escaping(self):
        rec = decode_frame(hook.build_record(
            base_event(tool_input={"a/b~c": "z" * (17 * KIB)})))
        self.assertIn("/tool_input/a~1b~0c", rec["audit"]["truncated"])

    def test_top_level_string_truncated(self):
        prompt = "p" * (40 * KIB)
        event = base_event(hook_event_name="UserPromptSubmit", prompt=prompt)
        rec = decode_frame(hook.build_record(event))
        self.assertEqual(len(rec["prompt"]), 16 * KIB)
        self.assertEqual(rec["audit"]["truncated"]["/prompt"]["length"], 40 * KIB)

    def test_long_key_truncated_without_collision(self):
        k1 = "k" * (20 * KIB) + "1"
        k2 = "k" * (20 * KIB) + "2"
        rec = decode_frame(hook.build_record(base_event(tool_input={k1: 1, k2: 2})))
        keys = list(rec["tool_input"])
        self.assertEqual(len(keys), 2)
        self.assertNotEqual(keys[0], keys[1])
        for k in keys:
            self.assertLessEqual(len(k.encode()), 16 * KIB + 17)
        entries = [v for p, v in rec["audit"]["truncated"].items()
                   if p.startswith("/tool_input/")]
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(e.get("key") for e in entries))

    def test_lone_surrogate_does_not_crash(self):
        event = json.loads('{"hook_event_name": "Stop", "x": "a\\ud800b"}')
        rec = decode_frame(hook.build_record(event))
        self.assertEqual(rec["x"], "a\ud800b")

    def test_write_of_1_mib(self):
        content = "line of source code\n" * (MIB // 20 + 1)   # > 1 MiB
        event = base_event(tool_input={"file_path": "/w/big.txt",
                                       "content": content})
        frame = hook.build_record(event)
        self.assertLessEqual(len(frame), MIB)
        rec = decode_frame(frame)
        self.assertEqual(rec["tool_input"]["file_path"], "/w/big.txt")
        self.assertEqual(rec["tool_input"]["content"], content[:16 * KIB])
        self.assertEqual(rec["audit"]["truncated"], {
            "/tool_input/content": {"length": len(content.encode()),
                                    "sha256": sha(content.encode())}})

    def test_non_object_rejected(self):
        with self.assertRaises(hook.HookError):
            hook.build_record(["not", "an", "object"])


class StubTests(unittest.TestCase):

    def test_many_fields_fall_back_to_stubs(self):
        # 100 strings of 15 KiB each: none is truncated, but together they
        # exceed 1 MiB, so tool_input and tool_response become stubs.
        tool_input = {f"f{i}": "a" * (15 * KIB) for i in range(100)}
        tool_response = {"stdout": "short"}
        event = base_event(hook_event_name="PostToolUse",
                           tool_input=tool_input, tool_response=tool_response)
        frame = hook.build_record(event)
        self.assertLessEqual(len(frame), MIB)
        rec = decode_frame(frame)
        compact_in = json.dumps(tool_input, ensure_ascii=False,
                                separators=(",", ":")).encode()
        compact_out = json.dumps(tool_response, ensure_ascii=False,
                                 separators=(",", ":")).encode()
        self.assertEqual(rec["tool_input"], {"length": len(compact_in),
                                             "sha256": sha(compact_in)})
        self.assertEqual(rec["tool_response"], {"length": len(compact_out),
                                                "sha256": sha(compact_out)})
        self.assertEqual(rec["audit"]["truncated"]["/tool_input"],
                         rec["tool_input"])
        self.assertEqual(rec["audit"]["truncated"]["/tool_response"],
                         rec["tool_response"])
        self.assertEqual(rec["session_id"], event["session_id"])

    def test_stub_drops_nested_truncation_entries(self):
        tool_input = {f"f{i}": "b" * (20 * KIB) for i in range(80)}
        frame = hook.build_record(base_event(tool_input=tool_input))
        rec = decode_frame(frame)
        self.assertIn("/tool_input", rec["audit"]["truncated"])
        self.assertFalse([p for p in rec["audit"]["truncated"]
                          if p.startswith("/tool_input/")])

    def test_other_large_field_stubbed_last(self):
        event = base_event(tool_input={"c": "x"},
                           extra=[str(i) * 10 for i in range(200000)])
        frame = hook.build_record(event)
        self.assertLessEqual(len(frame), MIB)
        rec = decode_frame(frame)
        self.assertEqual(set(rec["extra"]), {"length", "sha256"})
        self.assertIn("/extra", rec["audit"]["truncated"])


class ExchangeTests(unittest.TestCase):
    """Run the hook as a real subprocess against a fake collector."""

    def setUp(self):
        self.dir = S.short_tmpdir(self)
        self.sock = os.path.join(self.dir, "hook.sock")

    def run_hook(self, stdin, *args, timeout=30):
        argv = [str(S.HOOK), "--socket", self.sock, *args]
        return subprocess.run(argv, input=stdin, capture_output=True,
                              timeout=timeout)

    def start(self, reply):
        collector = S.FakeCollector(self.sock, reply)
        self.addCleanup(collector.close)
        return collector

    def assert_failure(self, proc, fragment):
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        lines = proc.stderr.decode().splitlines()
        self.assertEqual(len(lines), 1, lines)
        self.assertIn(fragment, lines[0])

    def test_ok_reply(self):
        collector = self.start(b"ok")
        event = base_event(tool_input={"content": "c" * (20 * KIB)})
        proc = self.run_hook(json.dumps(event).encode())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, b"")
        self.assertEqual(proc.stderr, b"")
        collector.done.wait(5)
        length, body = collector.frame
        self.assertEqual(length, len(body))
        rec = json.loads(body)
        self.assertEqual(rec["tool_use_id"], "toolu_01")
        self.assertIn("/tool_input/content", rec["audit"]["truncated"])

    def test_bad_reply(self):
        self.start(b"no")
        self.assert_failure(self.run_hook(b'{"a": 1}'), "did not acknowledge")

    def test_eof_without_reply(self):
        self.start(None)
        self.assert_failure(self.run_hook(b'{"a": 1}'), "did not acknowledge")

    def test_no_socket(self):
        self.assert_failure(self.run_hook(b'{"a": 1}'), "cannot reach collector")

    def test_invalid_json(self):
        self.start(b"ok")
        self.assert_failure(self.run_hook(b'{"a": '), "cannot parse")

    def test_unknown_argument_exits_1_not_2(self):
        proc = subprocess.run([str(S.HOOK), "--bogus"], input=b"{}",
                              capture_output=True, timeout=30)
        self.assert_failure(proc, "unknown argument")

    def test_stdin_over_64_mib(self):
        self.start(b"ok")
        data = b'{"x": "' + b"a" * (64 * MIB) + b'"}'
        self.assert_failure(self.run_hook(data), "exceeds 64 MiB")

    def test_large_write_end_to_end(self):
        collector = self.start(b"ok")
        content = "z" * (2 * MIB)
        proc = self.run_hook(json.dumps(
            base_event(tool_input={"file_path": "/f", "content": content})).encode())
        self.assertEqual(proc.returncode, 0, proc.stderr)
        collector.done.wait(5)
        length, _ = collector.frame
        self.assertLessEqual(length + 4, MIB)

    def test_timeout(self):
        # In-process with a short timeout, so the test does not take 5 s.
        self.start("hang")
        frame = hook.build_record(base_event())
        start = time.monotonic()
        with mock.patch.object(hook, "TIMEOUT", 0.3):
            with self.assertRaisesRegex(hook.HookError, "timed out"):
                hook.send(frame, self.sock)
        self.assertLess(time.monotonic() - start, 3)

    def test_default_socket_path(self):
        self.assertEqual(hook.parse_args([]), "/run/agent-log-shipper/hook.sock")

    def test_socket_path_not_taken_from_environment(self):
        # The agent can influence the environment; only --socket counts.
        with mock.patch.dict(os.environ,
                             {"AGENT_AUDIT_HOOK_SOCKET": "/tmp/evil.sock"}):
            self.assertEqual(hook.parse_args([]),
                             "/run/agent-log-shipper/hook.sock")

    def test_shebang_isolated_mode(self):
        with open(S.HOOK, "rb") as f:
            self.assertEqual(f.readline(), b"#!/usr/bin/python3 -I\n")
        self.assertTrue(os.access(S.HOOK, os.X_OK))

    def test_read_stdin_limit(self):
        fake = mock.Mock()
        fake.buffer = io.BytesIO(b"x" * 11)
        with mock.patch.object(hook, "MAX_STDIN", 10), \
             mock.patch.object(hook.sys, "stdin", fake):
            with self.assertRaises(hook.HookError):
                hook.read_stdin()


if __name__ == "__main__":
    unittest.main()
