"""Tests for agent-run, using --print and a fake --root (no root needed)."""

import os
import re
import shlex
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auditsupport as S  # noqa: E402

SETTINGS_D = "etc/claude-code/managed-settings.d"
RUN_ID_RE = r"\d{8}T\d{6}-[0-9a-f]{8}"


def write(path, text, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, mode)


class AgentRunTests(unittest.TestCase):

    def setUp(self):
        # Short path: the collector socket lives under the fake root.
        self.root = S.short_tmpdir(self)
        r = self.root
        write(f"{r}/{SETTINGS_D}/50-agent-audit.json", "{}")
        write(f"{r}/usr/local/lib/agent-audit/claude-audit-hook", "#!/bin/sh\n", 0o755)
        write(f"{r}/opt/claude-code/9.9.9/claude", "#!/bin/sh\n", 0o755)
        os.makedirs(f"{r}/usr/local/bin")
        os.symlink("/opt/claude-code/9.9.9/claude", f"{r}/usr/local/bin/claude")
        write(f"{r}/proc/sys/kernel/yama/ptrace_scope", "1\n")
        os.makedirs(f"{r}/run/agent-log-shipper")
        sock = S.bind_socket(f"{r}/run/agent-log-shipper/hook.sock")
        self.addCleanup(sock.close)
        self.set_nft(ok=True)
        self.set_virt(vm=False)
        self.project = os.path.join(r, "project dir")   # space on purpose
        os.makedirs(self.project)

    # --- fixtures -------------------------------------------------------

    def set_nft(self, ok):
        write(f"{self.root}/usr/sbin/nft",
              "#!/bin/sh\n" + ("exit 0\n" if ok else "exit 1\n"), 0o755)

    def set_virt(self, vm):
        write(f"{self.root}/usr/bin/systemd-detect-virt",
              "#!/bin/sh\n" + ("exit 0\n" if vm else "exit 1\n"), 0o755)

    def enable_egress(self):
        write(f"{self.root}/{SETTINGS_D}/40-agent-egress.json", "{}")

    def run_ar(self, *args, root=True, print_=True):
        argv = [str(S.AGENT_RUN)]
        if print_:
            argv.append("--print")
        if root:
            argv += ["--root", self.root]
        argv += list(args)
        env = dict(os.environ, TERM="xterm-256color")
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=30, env=env)

    def launch(self, *args):
        proc = self.run_ar("--dir", self.project, *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return shlex.split(proc.stdout), proc.stderr

    def props(self, argv):
        """The -p NAME=VALUE properties before the `--` separator."""
        out = {}
        head = argv[:argv.index("--")]
        for i, a in enumerate(head):
            if a == "-p":
                name, _, value = head[i + 1].partition("=")
                out[name] = value
        return out

    # --- command shape --------------------------------------------------

    def test_host_without_egress(self):
        argv, err = self.launch("--env", "host")
        self.assertIn("WARNING: egress control not installed", err)
        self.assertEqual(argv[0], "/usr/bin/systemd-run")
        for flag in ("--uid=agent", "--gid=agent", "--pty", "--wait", "--collect"):
            self.assertIn(flag, argv)
        unit = [a for a in argv if a.startswith("--unit=")]
        self.assertEqual(len(unit), 1)
        self.assertRegex(unit[0], rf"^--unit=agent-run-{RUN_ID_RE}$")
        run_id = unit[0].split("agent-run-", 1)[1]
        self.assertIn(f"--setenv=AGENT_RUN_ID={run_id}", argv)
        self.assertIn("--setenv=TERM=xterm-256color", argv)
        p = self.props(argv)
        self.assertEqual(p["PAMName"], "agent-run")
        self.assertEqual(p["WorkingDirectory"], os.path.realpath(self.project))
        self.assertEqual(p["NoNewPrivileges"], "yes")
        self.assertEqual(p["RestrictAddressFamilies"],
                         "AF_UNIX AF_INET AF_INET6 AF_NETLINK")
        self.assertEqual(p["SystemCallArchitectures"], "native")
        self.assertEqual(p["SystemCallFilter"],
                         "~io_uring_setup io_uring_enter io_uring_register")
        self.assertEqual(p["SystemCallErrorNumber"], "EPERM")
        self.assertEqual(p["InaccessiblePaths"],
                         "-/run/systemd/resolve -/run/dbus -/run/avahi-daemon -/run/cups")
        self.assertNotIn("IPAddressDeny", p)
        self.assertNotIn("IPAddressAllow", p)
        tail = argv[argv.index("--"):]
        self.assertEqual(tail, ["--", "/usr/local/bin/claude",
                                "--dangerously-skip-permissions"])

    def test_host_with_egress(self):
        self.enable_egress()
        argv, err = self.launch("--env", "host")
        self.assertNotIn("WARNING", err)
        p = self.props(argv)
        self.assertEqual(p["IPAddressDeny"], "any")
        self.assertEqual(p["IPAddressAllow"], "localhost")
        self.assertIn("InaccessiblePaths", p)

    def test_vm_without_egress(self):
        argv, err = self.launch("--env", "vm")
        self.assertIn("WARNING: egress control not installed", err)
        p = self.props(argv)
        self.assertNotIn("InaccessiblePaths", p)
        self.assertNotIn("IPAddressDeny", p)
        self.assertNotIn("IPAddressAllow", p)

    def test_vm_with_egress(self):
        self.enable_egress()
        self.set_nft(ok=False)   # the nft check is host-only
        argv, err = self.launch("--env", "vm")
        self.assertNotIn("WARNING", err)
        p = self.props(argv)
        self.assertEqual(p["IPAddressDeny"], "any")
        self.assertEqual(p["IPAddressAllow"], "localhost 192.168.123.1")
        self.assertNotIn("InaccessiblePaths", p)

    def test_env_default_detects_vm(self):
        self.set_virt(vm=True)
        argv, _ = self.launch()
        self.assertNotIn("InaccessiblePaths", self.props(argv))

    def test_env_default_detects_host(self):
        self.set_virt(vm=False)
        argv, _ = self.launch()
        self.assertIn("InaccessiblePaths", self.props(argv))

    def test_claude_args_passed_through(self):
        argv, _ = self.launch("--env", "host", "--", "-p", "hello world", "--resume")
        self.assertEqual(argv[-4:], ["--dangerously-skip-permissions",
                                     "-p", "hello world", "--resume"])

    def test_run_ids_differ(self):
        a, _ = self.launch("--env", "host")
        b, _ = self.launch("--env", "host")
        ua = [x for x in a if x.startswith("--unit=")]
        ub = [x for x in b if x.startswith("--unit=")]
        self.assertNotEqual(ua, ub)

    # --- refusals -------------------------------------------------------

    def assert_refused(self, fragment, *args):
        proc = self.run_ar("--dir", self.project, "--env", "host", *args)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertEqual(proc.stdout, "")
        self.assertIn(fragment, proc.stderr)
        return proc

    def test_refuses_without_managed_settings(self):
        os.unlink(f"{self.root}/{SETTINGS_D}/50-agent-audit.json")
        self.assert_refused("managed settings missing")

    def test_refuses_without_hook(self):
        os.unlink(f"{self.root}/usr/local/lib/agent-audit/claude-audit-hook")
        self.assert_refused("audit hook missing")

    def test_refuses_without_collector_socket(self):
        os.unlink(f"{self.root}/run/agent-log-shipper/hook.sock")
        self.assert_refused("hook collector socket missing")

    def test_refuses_when_socket_is_regular_file(self):
        path = f"{self.root}/run/agent-log-shipper/hook.sock"
        os.unlink(path)
        write(path, "")
        self.assert_refused("hook collector socket missing")

    def test_refuses_when_audit_degraded(self):
        write(f"{self.root}/run/agent-log-shipper/audit-degraded", "")
        self.assert_refused("audit-degraded")

    def test_refuses_ptrace_scope_0(self):
        write(f"{self.root}/proc/sys/kernel/yama/ptrace_scope", "0\n")
        self.assert_refused("must be >= 1")

    def test_accepts_ptrace_scope_2(self):
        write(f"{self.root}/proc/sys/kernel/yama/ptrace_scope", "2\n")
        self.launch("--env", "host")

    def test_refuses_without_yama(self):
        os.unlink(f"{self.root}/proc/sys/kernel/yama/ptrace_scope")
        self.assert_refused("cannot read")

    def test_refuses_claude_outside_store(self):
        link = f"{self.root}/usr/local/bin/claude"
        os.unlink(link)
        os.symlink("/home/agent/.local/share/claude/versions/9.9.9", link)
        self.assert_refused("is not a symlink to /opt/claude-code/")

    def test_refuses_claude_dotdot(self):
        link = f"{self.root}/usr/local/bin/claude"
        os.unlink(link)
        os.symlink("/opt/claude-code/../../home/agent/claude", link)
        self.assert_refused("is not a symlink to /opt/claude-code/")

    def test_refuses_missing_claude_binary(self):
        os.unlink(f"{self.root}/opt/claude-code/9.9.9/claude")
        self.assert_refused("not an executable regular file")

    def test_refuses_host_egress_without_nft_table(self):
        self.enable_egress()
        self.set_nft(ok=False)
        self.assert_refused("agent_egress is not loaded")

    def test_reports_every_failure(self):
        os.unlink(f"{self.root}/run/agent-log-shipper/hook.sock")
        write(f"{self.root}/proc/sys/kernel/yama/ptrace_scope", "0\n")
        proc = self.assert_refused("hook collector socket missing")
        self.assertIn("must be >= 1", proc.stderr)

    def test_refuses_bad_env(self):
        proc = self.run_ar("--dir", self.project, "--env", "cloud")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--env must be host or vm", proc.stderr)

    def test_refuses_missing_project(self):
        proc = self.run_ar("--dir", os.path.join(self.root, "nope"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("project directory does not exist", proc.stderr)

    def test_root_only_with_print(self):
        proc = self.run_ar("--dir", self.project, print_=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--root is only allowed together with --print",
                      proc.stderr)

    @unittest.skipIf(os.geteuid() == 0, "running as root")
    def test_refuses_non_root_launch(self):
        proc = self.run_ar("--dir", self.project, root=False, print_=False)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("must be run as root", proc.stderr)

    def test_unknown_option(self):
        proc = self.run_ar("--frobnicate")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("unknown argument", proc.stderr)


if __name__ == "__main__":
    unittest.main()
