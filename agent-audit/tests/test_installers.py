"""Tests for install.sh and install-claude.sh in --root staging mode."""

import hashlib
import os
import pwd
import stat
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auditsupport as S  # noqa: E402

ME = pwd.getpwuid(os.getuid()).pw_name
SAMPLE_AUDITD_CONF = """\
#
# This file controls the configuration of the audit daemon
#
local_events = yes
log_file = /var/log/audit/audit.log
max_log_file_action = keep_logs
space_left_action = SYSLOG
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = HALT
"""


def mode(path):
    return stat.S_IMODE(os.lstat(path).st_mode)


def read(path):
    with open(path) as f:
        return f.read()


class InstallTests(unittest.TestCase):

    def setUp(self):
        self.root = S.short_tmpdir(self)

    def install(self, *args, check=True):
        argv = [str(S.INSTALL), "--root", self.root, "--agent-user", ME,
                "--admin-user", "admin-x", *args]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        if check:
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        return proc

    def path(self, rel):
        return os.path.join(self.root, rel.lstrip("/"))

    def test_layout_and_modes(self):
        self.install()
        expected = {
            "/usr/local/lib/agent-audit/claude-audit-hook": 0o755,
            "/usr/local/sbin/agent-run": 0o755,
            "/etc/claude-code/managed-settings.d/50-agent-audit.json": 0o644,
            "/etc/pam.d/agent-run": 0o644,
            "/etc/audit/rules.d/50-agent.rules": 0o640,
            "/etc/sysctl.d/60-agent-ptrace.conf": 0o644,
            "/etc/cron.allow": 0o644,
            "/etc/at.allow": 0o644,
        }
        for rel, m in expected.items():
            self.assertTrue(os.path.isfile(self.path(rel)), rel)
            self.assertEqual(mode(self.path(rel)), m, rel)
        same = {
            "/usr/local/lib/agent-audit/claude-audit-hook": "claude-audit-hook",
            "/usr/local/sbin/agent-run": "agent-run",
            "/etc/claude-code/managed-settings.d/50-agent-audit.json":
                "managed-settings.d/50-agent-audit.json",
            "/etc/pam.d/agent-run": "pam.d/agent-run",
            "/etc/sysctl.d/60-agent-ptrace.conf": "sysctl.d/60-agent-ptrace.conf",
        }
        for rel, src in same.items():
            expected = read(S.AUDIT_DIR / src)
            if src == "agent-run":   # install.sh sets AGENT_USER to --agent-user
                expected = expected.replace('\nAGENT_USER="agent" ', f'\nAGENT_USER="{ME}" ')
            self.assertEqual(read(self.path(rel)), expected, rel)

    def test_audit_rules_substituted(self):
        self.install()
        rules = read(self.path("/etc/audit/rules.d/50-agent.rules"))
        self.assertNotIn("@AGENT_UID@", rules)
        self.assertIn(f"-F uid={os.getuid()} -k agent-exec", rules)
        self.assertEqual(rules.count(f"uid={os.getuid()}"), 6)
        self.assertNotIn("@AGENT_HOME@", rules)
        self.assertIn(f"-w {pwd.getpwnam(ME).pw_dir}/.ssh -p r", rules)

    def test_agent_run_gets_agent_user(self):
        self.install()
        script = read(self.path("/usr/local/sbin/agent-run"))
        self.assertIn(f'\nAGENT_USER="{ME}" ', script)

    def test_watch_with_missing_parent_disabled(self):
        self.install()
        rules = read(self.path("/etc/audit/rules.d/50-agent.rules"))
        self.assertIn("# disabled by install.sh (missing /etc/libvirt/qemu): "
                      "-w /etc/libvirt/qemu/networks/", rules)
        # /etc exists in the staging root (install.sh created it).
        self.assertRegex(rules, r"(?m)^-w /etc/claude-code/ -p wa -k agent-policy$")

    def test_watch_with_existing_parent_enabled(self):
        os.makedirs(self.path("/etc/libvirt/qemu"))
        self.install()
        rules = read(self.path("/etc/audit/rules.d/50-agent.rules"))
        self.assertRegex(rules, r"(?m)^-w /etc/libvirt/qemu/networks/ -p wa")

    def test_cron_and_at_allow(self):
        os.makedirs(self.path("/etc"))
        with open(self.path("/etc/cron.allow"), "w") as f:
            f.write(f"alice\n{ME}\n")
        self.install()
        self.assertEqual(read(self.path("/etc/cron.allow")).split(),
                         ["alice", "root", "admin-x"])
        self.assertEqual(read(self.path("/etc/at.allow")).split(),
                         ["root", "admin-x"])

    def test_auditd_conf_edit_and_backup(self):
        os.makedirs(self.path("/etc/audit"))
        conf = self.path("/etc/audit/auditd.conf")
        with open(conf, "w") as f:
            f.write(SAMPLE_AUDITD_CONF)
        self.install()
        text = read(conf)
        self.assertIn("\nadmin_space_left_action = SUSPEND\n", text)
        self.assertIn("\ndisk_full_action = SUSPEND\n", text)
        self.assertIn("\nmax_log_file_action = ROTATE\n", text)
        self.assertIn("\ndisk_error_action = SUSPEND\n", text)   # appended
        self.assertIn("\nadmin_space_left = 50\n", text)         # untouched
        self.assertNotIn("halt", text.lower())
        self.assertEqual(read(conf + ".agent-audit.bak"), SAMPLE_AUDITD_CONF)

        # Idempotent: a second run changes nothing and keeps the backup.
        proc = self.install()
        self.assertEqual(read(conf), text)
        self.assertEqual(read(conf + ".agent-audit.bak"), SAMPLE_AUDITD_CONF)
        self.assertNotIn("installed:", proc.stdout)
        self.assertNotIn("edited:", proc.stdout)
        self.assertIn("unchanged: /etc/audit/auditd.conf", proc.stdout)

    def test_skips_system_commands(self):
        proc = self.install()
        for cmd in ("augenrules --load", "systemctl enable --now auditd.service",
                    "loginctl disable-linger"):
            self.assertIn(f"skipped (--root): {cmd}", proc.stdout)

    def test_dry_run_writes_nothing(self):
        proc = subprocess.run(
            [str(S.INSTALL), "--dry-run", "--root", self.root,
             "--agent-user", ME, "--admin-user", "admin-x"],
            capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("would install: /usr/local/sbin/agent-run", proc.stdout)
        self.assertEqual(os.listdir(self.root), [])

    def test_refuses_root_as_agent_user(self):
        proc = subprocess.run([str(S.INSTALL), "--root", self.root,
                               "--agent-user", "root"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)

    def test_admin_user_defaults_to_sudo_user(self):
        base = [str(S.INSTALL), "--root", self.root, "--agent-user", ME]
        env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
        proc = subprocess.run(base, capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--admin-user", proc.stderr)
        proc = subprocess.run(base, capture_output=True, text=True, timeout=60,
                              env={**env, "SUDO_USER": "root"})
        self.assertEqual(proc.returncode, 1)
        proc = subprocess.run(base, capture_output=True, text=True, timeout=60,
                              env={**env, "SUDO_USER": "admin-y"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        with open(self.path("/etc/cron.allow")) as f:
            self.assertIn("admin-y", f.read().split())

    def test_refuses_unknown_agent_user(self):
        proc = subprocess.run([str(S.INSTALL), "--root", self.root,
                               "--agent-user", "no-such-user-xyz"],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no such user", proc.stderr)

    @unittest.skipIf(os.geteuid() == 0, "running as root")
    def test_refuses_non_root_real_install(self):
        proc = subprocess.run([str(S.INSTALL), "--agent-user", ME],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("must be run as root", proc.stderr)


class InstallClaudeTests(unittest.TestCase):

    def setUp(self):
        self.dir = S.short_tmpdir(self)
        self.root = os.path.join(self.dir, "root")

    def fake_binary(self, name, version_line, extra=""):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(f"#!/bin/sh\n# {extra}\necho '{version_line}'\n")
        os.chmod(path, 0o700)   # deliberately not 0755
        return path

    def run_ic(self, binary, *args):
        return subprocess.run([str(S.INSTALL_CLAUDE), "--root", self.root,
                               "--binary", binary, *args],
                              capture_output=True, text=True, timeout=60)

    def link(self):
        return os.readlink(os.path.join(self.root, "usr/local/bin/claude"))

    def test_install_and_symlink(self):
        b = self.fake_binary("claude", "1.2.3 (Claude Code)")
        proc = self.run_ic(b)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        dest = os.path.join(self.root, "opt/claude-code/1.2.3/claude")
        self.assertEqual(mode(dest), 0o755)
        self.assertEqual(read(dest), read(b))
        self.assertEqual(self.link(), "/opt/claude-code/1.2.3/claude")
        self.assertEqual(mode(os.path.join(self.root, "opt/claude-code")), 0o755)
        # No staging leftovers.
        self.assertEqual(sorted(os.listdir(os.path.join(self.root, "opt/claude-code"))),
                         ["1.2.3"])
        self.assertEqual(os.listdir(os.path.join(self.root, "usr/local/bin")),
                         ["claude"])

    def test_sha256_verified(self):
        b = self.fake_binary("claude", "1.2.3 (Claude Code)")
        with open(b, "rb") as f:
            good = hashlib.sha256(f.read()).hexdigest()
        proc = self.run_ic(b, "--sha256", "0" * 64)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("SHA-256 mismatch", proc.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.root, "opt/claude-code/1.2.3")))
        self.assertFalse(os.path.lexists(os.path.join(self.root, "usr/local/bin/claude")))
        proc = self.run_ic(b, "--sha256", good.upper())
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_upgrade_swaps_symlink_and_keeps_old(self):
        self.assertEqual(self.run_ic(self.fake_binary("a", "1.0.0 (Claude Code)")).returncode, 0)
        self.assertEqual(self.run_ic(self.fake_binary("b", "1.1.0 (Claude Code)")).returncode, 0)
        self.assertEqual(self.link(), "/opt/claude-code/1.1.0/claude")
        self.assertTrue(os.path.exists(os.path.join(self.root, "opt/claude-code/1.0.0/claude")))
        # Rolling back is just re-running with the old binary.
        self.assertEqual(self.run_ic(self.fake_binary("a", "1.0.0 (Claude Code)")).returncode, 0)
        self.assertEqual(self.link(), "/opt/claude-code/1.0.0/claude")

    def test_same_version_different_contents_refused(self):
        self.assertEqual(self.run_ic(self.fake_binary("a", "1.0.0 (Claude Code)")).returncode, 0)
        proc = self.run_ic(self.fake_binary("b", "1.0.0 (Claude Code)", extra="different"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("different contents", proc.stderr)

    def test_bad_version_rejected(self):
        for line in ("../../etc (Claude Code)", "", "v1 (Claude Code)"):
            proc = self.run_ic(self.fake_binary("x", line))
            self.assertEqual(proc.returncode, 1, line)
        self.assertFalse(os.path.lexists(os.path.join(self.root, "usr/local/bin/claude")))

    def test_missing_binary(self):
        proc = self.run_ic(os.path.join(self.dir, "nope"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not a regular file", proc.stderr)

    @unittest.skipIf(os.geteuid() == 0, "running as root")
    def test_refuses_non_root_real_install(self):
        b = self.fake_binary("claude", "1.2.3 (Claude Code)")
        proc = subprocess.run([str(S.INSTALL_CLAUDE), "--binary", b],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("must be run as root", proc.stderr)


if __name__ == "__main__":
    unittest.main()
