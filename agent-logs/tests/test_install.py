"""Installers (staged with --root), unit files, templates, and scripts."""

import configparser
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import helpers  # noqa: E402

C = helpers.COMPONENT


def run(script, *args):
    return subprocess.run(["bash", os.path.join(C, script), *args], capture_output=True,
                          text=True, timeout=60)


def snapshot(root):
    out = {}
    for dirpath, dirs, files in os.walk(root):
        for name in dirs + files:
            p = os.path.join(dirpath, name)
            st = os.lstat(p)
            content = None
            if stat.S_ISLNK(st.st_mode):
                content = os.readlink(p)
            elif stat.S_ISREG(st.st_mode):
                with open(p, "rb") as f:
                    content = f.read()
            out[os.path.relpath(p, root)] = (stat.S_IMODE(st.st_mode), content)
    return out


def unit(name):
    cp = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    cp.optionxform = str
    cp.read(os.path.join(C, "systemd", name))
    return cp


class InstallEnvTest(unittest.TestCase):
    def test_modes(self):
        for mode in ("host", "vm", "local"):
            root = helpers.tempdir(self)
            out = run("install-env.sh", "--mode", mode, "--root", root)
            self.assertEqual(out.returncode, 0, out.stderr)
            prog = os.path.join(root, "usr/local/lib/agent-logs/agent-log-shipper")
            self.assertEqual(stat.S_IMODE(os.stat(prog).st_mode), 0o755)
            self.assertTrue(os.path.exists(os.path.join(
                root, "etc/systemd/system/agent-log-shipper.service")))
            with open(os.path.join(root, "etc/agent-tools/agent-log-shipper.env")) as f:
                env = f.read()
                self.assertIn(f"SHIPPER_MODE={mode}\n", env)
                self.assertIn("AGENT_USER=agent\n", env)
            self.assertFalse(os.path.exists(os.path.join(root, "etc/claude-code")))
            self.assertIn("skipping: systemctl", out.stdout)

    def test_idempotent(self):
        root = helpers.tempdir(self)
        run("install-env.sh", "--mode", "vm", "--otel", "--root", root)
        first = snapshot(root)
        out = run("install-env.sh", "--mode", "vm", "--otel", "--root", root)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(snapshot(root), first)

    def test_otel_dropin(self):
        for mode, addr in (("host", "127.0.0.1"), ("vm", "192.168.123.1")):
            root = helpers.tempdir(self)
            self.assertEqual(run("install-env.sh", "--mode", mode, "--otel", "--root", root)
                             .returncode, 0)
            path = os.path.join(root, "etc/claude-code/managed-settings.d/45-agent-otel.json")
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o644)
            with open(path) as f:
                env = json.load(f)["env"]
            self.assertEqual(env["OTEL_EXPORTER_OTLP_ENDPOINT"], f"http://{addr}:4318")
            self.assertEqual(env["OTEL_EXPORTER_OTLP_PROTOCOL"], "http/json")

    def test_errors(self):
        root = helpers.tempdir(self)
        self.assertNotEqual(run("install-env.sh", "--root", root).returncode, 0)
        self.assertNotEqual(run("install-env.sh", "--mode", "bogus", "--root", root).returncode, 0)
        self.assertNotEqual(run("install-env.sh", "--mode", "local", "--otel", "--root", root)
                            .returncode, 0)
        if os.getuid() != 0:
            out = run("install-env.sh", "--mode", "host")
            self.assertNotEqual(out.returncode, 0)
            self.assertIn("must run as root", out.stderr)

    def test_dry_run_changes_nothing(self):
        root = helpers.tempdir(self)
        out = run("install-env.sh", "--mode", "host", "--dry-run", "--root", root)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("+ install", out.stdout)
        self.assertEqual(os.listdir(root), [])


class InstallHostTest(unittest.TestCase):
    def test_staged_install(self):
        root = helpers.tempdir(self)
        out = run("install-host.sh", "--root", root)
        self.assertEqual(out.returncode, 0, out.stderr)
        for path, mode in (("usr/local/lib/agent-logs/agent-logd", 0o755),
                           ("usr/local/lib/agent-logs/agent-log", 0o755),
                           ("etc/sysusers.d/agent-logs.conf", 0o644),
                           ("etc/tmpfiles.d/agent-logs.conf", 0o644),
                           ("etc/modules-load.d/agent-logs.conf", 0o644),
                           ("etc/agent-tools/envs.conf", 0o644),
                           ("var/log/agent-audit", 0o2750)):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(root, path)).st_mode), mode, path)
        for u in ("agent-logd.service", "agent-logd-vsock.socket", "agent-logd-unix.socket",
                  "agent-logd-otlp.socket"):
            self.assertTrue(os.path.exists(os.path.join(root, "etc/systemd/system", u)))
        self.assertEqual(os.readlink(os.path.join(root, "usr/local/bin/agent-log")),
                         "/usr/local/lib/agent-logs/agent-log")
        # Idempotent, and an existing envs.conf is never overwritten.
        conf = os.path.join(root, "etc/agent-tools/envs.conf")
        with open(conf, "w") as f:
            f.write("mine cid=33\n")
        first = snapshot(root)
        self.assertEqual(run("install-host.sh", "--root", root).returncode, 0)
        self.assertEqual(snapshot(root), first)

    def test_reader_defaults_to_sudo_user(self):
        me = pwd.getpwuid(os.getuid()).pw_name
        env = {k: v for k, v in os.environ.items() if k != "SUDO_USER"}
        script = os.path.join(C, "install-host.sh")
        out = subprocess.run(["bash", script, "--dry-run"], capture_output=True, text=True,
                             timeout=60, env={**env, "SUDO_USER": me})
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"+ usermod -aG agent-audit {me}", out.stdout)
        for extra in ({}, {"SUDO_USER": "root"}):
            out = subprocess.run(["bash", script, "--dry-run"], capture_output=True, text=True,
                                 timeout=60, env={**env, **extra})
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertNotIn("usermod", out.stdout)
            self.assertIn("--reader USER", out.stderr)

    def test_otlp_flag_and_dry_run(self):
        out = run("install-host.sh", "--otlp", "--dry-run", "--root", helpers.tempdir(self))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("enable --now agent-logd-otlp.socket", out.stdout)


class ConfigFilesTest(unittest.TestCase):
    def test_shipper_unit(self):
        svc = unit("agent-log-shipper.service")["Service"]
        self.assertEqual(svc["User"], "root")
        self.assertEqual(svc["CapabilityBoundingSet"],
                         "CAP_SYS_PTRACE CAP_DAC_READ_SEARCH CAP_NET_BIND_SERVICE")
        self.assertEqual(svc["RestrictAddressFamilies"], "AF_UNIX AF_VSOCK")
        self.assertEqual(svc["ProtectSystem"], "strict")
        self.assertEqual(svc["ProtectHome"], "read-only")
        self.assertEqual(svc["RuntimeDirectory"], "agent-log-shipper")
        self.assertEqual(svc["RuntimeDirectoryMode"], "0755")
        self.assertEqual(svc["RuntimeDirectoryPreserve"], "yes")
        self.assertEqual(svc["StateDirectory"], "agent-log-shipper")
        self.assertEqual(svc["StateDirectoryMode"], "0700")
        self.assertIn("--mode ${SHIPPER_MODE}", svc["ExecStart"])
        self.assertIn("--agent-user ${AGENT_USER}", svc["ExecStart"])
        self.assertNotIn("ProtectProc", svc)      # would hide agent processes
        self.assertNotIn("PrivateUsers", svc)

    def test_logd_units(self):
        svc = unit("agent-logd.service")["Service"]
        self.assertEqual(svc["User"], "agent-logd")
        self.assertEqual(svc["CapabilityBoundingSet"], "")
        self.assertEqual(svc["RestrictAddressFamilies"], "AF_UNIX AF_VSOCK AF_INET AF_INET6")
        self.assertEqual(svc["ReadWritePaths"], "/var/log/agent-audit")
        self.assertEqual(svc["LogRateLimitIntervalSec"], "0")
        names = {}
        for name in ("vsock", "unix", "otlp"):
            sock = unit(f"agent-logd-{name}.socket")["Socket"]
            self.assertEqual(sock["Service"], "agent-logd.service")
            names[name] = sock["FileDescriptorName"]
        self.assertEqual(names, {"vsock": "vsock", "unix": "unix", "otlp": "otlp"})
        self.assertEqual(unit("agent-logd-vsock.socket")["Socket"]["ListenStream"], "vsock::700")
        unix = unit("agent-logd-unix.socket")["Socket"]
        self.assertEqual((unix["ListenStream"], unix["SocketMode"], unix["SocketUser"]),
                         ("/run/agent-logd/ingest.sock", "0600", "root"))
        with open(os.path.join(C, "systemd", "agent-logd-otlp.socket")) as f:
            text = f.read()
        self.assertIn("ListenStream=127.0.0.1:4318", text)
        self.assertIn("ListenStream=192.168.123.1:4318", text)
        self.assertIn("FreeBind=yes", text)

    def test_sysusers_and_tmpfiles(self):
        def lines(p):
            with open(os.path.join(C, p)) as f:
                return [ln.split() for ln in f if ln.strip() and not ln.startswith("#")]
        users = lines("sysusers.d/agent-logs.conf")
        self.assertIn(["g", "agent-audit", "-"], users)
        self.assertEqual(users[1][:2], ["u", "agent-logd"])
        self.assertEqual(lines("tmpfiles.d/agent-logs.conf"),
                         [["d", "/var/log/agent-audit", "2750", "agent-logd", "agent-audit", "-"]])

    def test_otel_template(self):
        with open(os.path.join(C, "managed-settings.d/45-agent-otel.json.in")) as f:
            text = f.read()
        self.assertIn("@OTLP@", text)
        env = json.loads(text.replace("@OTLP@", "127.0.0.1"))["env"]
        self.assertEqual(env["CLAUDE_CODE_ENABLE_TELEMETRY"], "1")
        self.assertEqual(set(env), {"CLAUDE_CODE_ENABLE_TELEMETRY", "OTEL_LOGS_EXPORTER",
                                    "OTEL_METRICS_EXPORTER", "OTEL_EXPORTER_OTLP_PROTOCOL",
                                    "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_LOG_TOOL_DETAILS"})

    def test_programs(self):
        for name in ("agent-log-shipper", "agent-logd", "agent-log"):
            path = os.path.join(C, name)
            self.assertTrue(os.access(path, os.X_OK), name)
            with open(path) as f:
                self.assertEqual(f.readline(), "#!/usr/bin/python3 -I\n")
            out = subprocess.run([helpers.python(), "-I", path, "--help"], capture_output=True,
                                 text=True, timeout=30)
            self.assertEqual(out.returncode, 0, out.stderr)

    def test_shell_scripts(self):
        scripts = [os.path.join(C, s) for s in ("install-env.sh", "install-host.sh")]
        for s in scripts:
            self.assertEqual(subprocess.run(["bash", "-n", s]).returncode, 0, s)
        if shutil.which("shellcheck"):
            out = subprocess.run(["shellcheck", *scripts], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stdout)


if __name__ == "__main__":
    unittest.main()
