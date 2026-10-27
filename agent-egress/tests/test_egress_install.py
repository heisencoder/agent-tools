"""Installer and configuration-file tests: run install-host.sh and
vm/install-vm.sh into a staging root (--root), and check the staged layout,
template substitution, JSON/XML validity, idempotency, and unit files."""

import json
import os
import re
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import egress_testlib as lib

EGRESS = lib.EGRESS_DIR
HOST_INSTALLER = EGRESS / "install-host.sh"
VM_INSTALLER = EGRESS / "vm" / "install-vm.sh"
PLACEHOLDER = re.compile(r"@[A-Z_]+@")


def run(cmd, check=True):
    result = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise AssertionError(f"{cmd} failed ({result.returncode}):\n"
                             f"{result.stdout}\n{result.stderr}")
    return result


def unit_lines(path):
    """Unit file as a list of (key, value), keeping repeated keys."""
    out = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line and not line.startswith(("#", ";", "[")):
            key, _, value = line.partition("=")
            out.append((key, value))
    return out


class TestHostInstaller(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, *extra, check=True):
        return run([HOST_INSTALLER, "--root", self.root, "--agent-uid", "4242", *extra],
                   check=check)

    def test_staged_layout(self):
        out = self.install("--dev-ports", "9000-9099", "--enable", "npm").stdout
        r = self.root
        # Proxy: identical copy, executable.
        proxy = r / "usr/local/lib/agent-egress/agent-egress-proxy"
        self.assertEqual(proxy.read_bytes(), lib.PROXY_PATH.read_bytes())
        self.assertEqual(proxy.stat().st_mode & 0o777, 0o755)
        # Profiles installed; anthropic, github, and npm enabled by relative symlink.
        profiles = sorted(p.name for p in (r / "etc/agent-egress/profiles").iterdir())
        self.assertEqual(profiles, sorted(p.name for p in (EGRESS / "allowlist.d").iterdir()))
        enabled = r / "etc/agent-egress/allowlist.d"
        self.assertEqual(sorted(p.name for p in enabled.iterdir()),
                         ["anthropic.list", "github.list", "npm.list"])
        for link in enabled.iterdir():
            self.assertTrue(link.is_symlink())
            self.assertEqual(os.readlink(link), f"../profiles/{link.name}")
            self.assertTrue(link.exists())
        # envs.conf installed from the example.
        self.assertEqual((r / "etc/agent-tools/envs.conf").read_text(),
                         (lib.REPO_DIR / "envs.conf.example").read_text())
        # nftables: substituted, no placeholders, never flush ruleset.
        host_nft = (r / "etc/agent-egress/agent-host.nft").read_text()
        self.assertIn("meta skuid 4242 jump agent_out", host_nft)
        self.assertIn("elements = { 9000-9099 }", host_nft)
        vm_nft = (r / "etc/agent-egress/agent-vmnet.nft").read_text()
        for text in (host_nft, vm_nft):
            self.assertIsNone(PLACEHOLDER.search(text))
            rules = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
            self.assertFalse(any("flush" in l for l in rules))
        self.assertIn("delete table inet agent_egress", host_nft)
        self.assertIn("delete table inet agent_vmnet", vm_nft)
        # systemd units and sysusers copied verbatim.
        for name in ["agent-egress-proxy.service", "agent-egress-proxy.socket",
                     "agent-egress-nft.service"]:
            self.assertEqual((r / "etc/systemd/system" / name).read_text(),
                             (EGRESS / "systemd" / name).read_text())
        self.assertTrue((r / "etc/sysusers.d/agent-egress.conf").is_file())
        # Privileged commands are skipped, not run.
        self.assertIn("skip       systemctl daemon-reload", out)
        self.assertIn("skip       virsh -c qemu:///system net-define", out)

    def test_managed_settings(self):
        self.install()
        path = self.root / "etc/claude-code/managed-settings.d/40-agent-egress.json"
        run(["python3", "-m", "json.tool", path])
        env = json.loads(path.read_text())["env"]
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:3128")
        self.assertEqual(env["http_proxy"], "http://127.0.0.1:3128")
        self.assertEqual(env["NO_PROXY"], "localhost,127.0.0.1,::1,127.0.0.1")
        self.assertEqual(env["CLAUDE_CODE_PROXY_RESOLVES_HOSTS"], "1")
        self.assertEqual(env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1")
        self.assertEqual((env["GIT_CONFIG_COUNT"], env["GIT_CONFIG_KEY_0"],
                          env["GIT_CONFIG_VALUE_0"]),
                         ("1", "url.https://github.com/.insteadOf", "git@github.com:"))
        self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_libvirt_network_from_envs_conf(self):
        conf = self.root / "etc/agent-tools/envs.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text("# mine\nvm-a cid=10 ip=192.168.123.10 mac=52:54:00:A9:00:10\n"
                        "vm-b cid=11 ip=192.168.123.11 mac=52:54:00:a9:00:11\n"
                        "vm-c cid=12\n")
        out = self.install().stdout
        self.assertIn("keeping    /etc/agent-tools/envs.conf", out)
        self.assertIn("vm-c has no mac= or ip=", out)
        self.assertEqual(conf.read_text().splitlines()[0], "# mine")   # not overwritten
        net = ET.parse(self.root / "etc/agent-egress/libvirt/agent-net.xml").getroot()
        self.assertEqual(net.findtext("name"), "agent-net")
        self.assertIsNone(net.find("forward"))
        self.assertEqual(net.find("dns").get("enable"), "no")
        self.assertEqual(net.find("bridge").get("name"), "virbr-agent")
        self.assertEqual(net.find("ip").get("address"), "192.168.123.1")
        hosts = [(h.get("name"), h.get("mac"), h.get("ip"))
                 for h in net.iterfind("ip/dhcp/host")]
        self.assertEqual(hosts, [("vm-a", "52:54:00:a9:00:10", "192.168.123.10"),
                                 ("vm-b", "52:54:00:a9:00:11", "192.168.123.11")])
        self.assertIsNone(net.find("ip/dhcp/range"))
        snippet = (self.root / "etc/agent-egress/libvirt/vm-b-interface.xml").read_text()
        self.assertIsNone(PLACEHOLDER.search(snippet))
        devices = ET.fromstring(f"<devices>{snippet}</devices>")
        iface = devices.find("interface")
        self.assertEqual(iface.find("source").get("network"), "agent-net")
        self.assertEqual(iface.find("mac").get("address"), "52:54:00:a9:00:11")
        self.assertEqual(iface.find("port").get("isolated"), "yes")
        self.assertEqual(iface.find("filterref").get("filter"), "clean-traffic")
        self.assertEqual(iface.find("filterref/parameter").get("value"), "192.168.123.11")
        self.assertEqual(devices.find("vsock/cid").get("address"), "11")

    def test_idempotent(self):
        self.install("--enable", "pypi")
        out = self.install("--enable", "pypi").stdout
        self.assertNotIn("installed", out)
        self.assertNotIn("(new)", out)
        self.assertIn("enabled    pypi", out)
        # Re-running without --enable leaves an extra profile enabled...
        self.install()
        self.assertTrue((self.root / "etc/agent-egress/allowlist.d/pypi.list").is_symlink())
        # ...and does not touch a file the admin put in its place.
        link = self.root / "etc/agent-egress/allowlist.d/github.list"
        link.unlink()
        link.write_text("github.com\n")
        out = self.install().stdout
        self.assertIn("leaving /etc/agent-egress/allowlist.d/github.list alone", out)
        self.assertFalse(link.is_symlink())

    def test_dry_run_changes_nothing(self):
        out = self.install("--dry-run").stdout
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertIn("would install /usr/local/lib/agent-egress/agent-egress-proxy", out)
        self.assertIn("would enable anthropic", out)

    def test_rejects_bad_input(self):
        for extra in (["--enable", "nonesuch"], ["--dev-ports", "1;2"],
                      ["--agent-uid", "0"], ["--bogus"]):
            with self.subTest(extra=extra):
                self.assertNotEqual(self.install(*extra, check=False).returncode, 0)
        conf = self.root / "etc/agent-tools/envs.conf"
        conf.parent.mkdir(parents=True)
        conf.write_text("vm-a cid=10 ip=10.0.0.5 mac=52:54:00:a9:00:10\n")
        result = self.install(check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not in 192.168.123.2-254", result.stderr)

    @unittest.skipIf(os.geteuid() == 0, "running as root")
    def test_requires_root_without_root_option(self):
        result = run([HOST_INSTALLER, "--agent-uid", "4242"], check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be run as root", result.stderr)


class TestVmInstaller(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, *extra):
        return run([VM_INSTALLER, "--root", self.root, *extra])

    def test_staged_files_and_idempotency(self):
        env_file = self.root / "etc/environment"
        env_file.parent.mkdir(parents=True)
        env_file.write_text('PATH="/usr/local/sbin:/usr/bin"\nhttp_proxy=http://old:1\n'
                            "export HTTPS_PROXY=http://old:2\nLANG=C.UTF-8\n")
        self.install()
        lines = env_file.read_text().splitlines()
        self.assertIn('PATH="/usr/local/sbin:/usr/bin"', lines)
        self.assertIn("LANG=C.UTF-8", lines)
        self.assertNotIn("http_proxy=http://old:1", lines)
        self.assertNotIn("export HTTPS_PROXY=http://old:2", lines)
        for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
            self.assertIn(f"{var}=http://192.168.123.1:3128", lines)
        for var in ("no_proxy", "NO_PROXY"):
            self.assertIn(f"{var}=localhost,127.0.0.1,::1,192.168.123.1", lines)

        apt = (self.root / "etc/apt/apt.conf.d/90agent-proxy").read_text()
        self.assertIn('Acquire::http::Proxy "http://192.168.123.1:3128/";', apt)
        self.assertIn('Acquire::https::Proxy "http://192.168.123.1:3128/";', apt)

        git = run(["git", "config", "--file", self.root / "etc/gitconfig", "--get-all",
                   "url.https://github.com/.insteadOf"]).stdout
        self.assertEqual(git, "git@github.com:\n")

        settings = self.root / "etc/claude-code/managed-settings.d/40-agent-egress.json"
        run(["python3", "-m", "json.tool", settings])
        env = json.loads(settings.read_text())["env"]
        self.assertEqual(env["HTTPS_PROXY"], "http://192.168.123.1:3128")
        self.assertEqual(env["no_proxy"], "localhost,127.0.0.1,::1,192.168.123.1")

        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        out = self.install().stdout
        self.assertNotIn("installed", out)
        self.assertNotIn("updated", out)
        after = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_dry_run_and_bad_proxy(self):
        self.install("--dry-run")
        self.assertEqual(list(self.root.iterdir()), [])
        result = run([VM_INSTALLER, "--root", self.root, "--proxy", "evil|x"], check=False)
        self.assertNotEqual(result.returncode, 0)


class TestUnitFiles(unittest.TestCase):
    def test_socket(self):
        lines = unit_lines(EGRESS / "systemd/agent-egress-proxy.socket")
        self.assertIn(("ListenStream", "127.0.0.1:3128"), lines)
        self.assertIn(("ListenStream", "192.168.123.1:3128"), lines)
        self.assertIn(("FreeBind", "yes"), lines)

    def test_proxy_service(self):
        lines = unit_lines(EGRESS / "systemd/agent-egress-proxy.service")
        for item in [("User", "agent-egress"), ("ProtectSystem", "strict"),
                     ("NoNewPrivileges", "yes"), ("PrivateTmp", "yes"),
                     ("CapabilityBoundingSet", ""), ("MemoryMax", "256M"),
                     ("LimitNOFILE", "4096"), ("LogRateLimitIntervalSec", "0"),
                     ("ExecStart", "/usr/bin/python3 -I "
                                   "/usr/local/lib/agent-egress/agent-egress-proxy")]:
            self.assertIn(item, lines)
        requires = " ".join(v for k, v in lines if k == "Requires").split()
        self.assertIn("agent-egress-nft.service", requires)
        self.assertIn("agent-egress-proxy.socket", requires)

    def test_nft_service(self):
        lines = unit_lines(EGRESS / "systemd/agent-egress-nft.service")
        for item in [("DefaultDependencies", "no"), ("Wants", "network-pre.target"),
                     ("Type", "oneshot"), ("RemainAfterExit", "yes"),
                     ("ExecStart", "/usr/sbin/nft -f /etc/agent-egress/agent-host.nft"),
                     ("ExecStart", "/usr/sbin/nft -f /etc/agent-egress/agent-vmnet.nft")]:
            self.assertIn(item, lines)
        self.assertIn("network-pre.target", dict(lines)["Before"].split())
        self.assertNotIn("ExecStop", dict(lines))

    def test_sysusers(self):
        text = (EGRESS / "sysusers.d/agent-egress.conf").read_text()
        self.assertRegex(text, r"(?m)^u agent-egress - ")


if __name__ == "__main__":
    unittest.main()
