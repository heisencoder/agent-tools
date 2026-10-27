"""Static checks of the shipped configuration: managed settings JSON, PAM,
sysctl, the audit rules grammar, and shell script syntax."""

import json
import os
import re
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import auditsupport as S  # noqa: E402

HOOK_PATH = "/usr/local/lib/agent-audit/claude-audit-hook"
TOOL_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"]
OTHER_EVENTS = ["SessionStart", "UserPromptSubmit", "SubagentStart",
                "SubagentStop", "Stop", "ConfigChange", "SessionEnd"]
PINNED_EMPTY = ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV",
                "ENV", "GCONV_PATH", "CLAUDE_CODE_SHELL_PREFIX"]


def read(rel):
    with open(S.AUDIT_DIR / rel) as f:
        return f.read()


class ManagedSettingsTests(unittest.TestCase):

    def setUp(self):
        self.s = json.loads(read("managed-settings.d/50-agent-audit.json"))

    def test_top_level(self):
        self.assertIs(self.s["allowManagedHooksOnly"], True)
        self.assertIs(self.s["disableAllHooks"], False)
        # Must not be set: it would reject --dangerously-skip-permissions.
        self.assertNotIn("disableBypassPermissionsMode",
                         self.s.get("permissions", {}))
        self.assertEqual(set(self.s), {"allowManagedHooksOnly",
                                       "disableAllHooks", "env", "hooks"})

    def test_env_pins(self):
        env = self.s["env"]
        self.assertEqual(env["DISABLE_AUTOUPDATER"], "1")
        for var in PINNED_EMPTY:
            self.assertEqual(env[var], "", var)
        self.assertTrue(all(isinstance(v, str) for v in env.values()))

    def test_every_hook_spelled_out(self):
        hooks = self.s["hooks"]
        self.assertEqual(set(hooks), set(TOOL_EVENTS + OTHER_EVENTS))
        for event, groups in hooks.items():
            self.assertEqual(len(groups), 1, event)
            group = groups[0]
            if event in TOOL_EVENTS:
                self.assertEqual(group["matcher"], "*", event)
            else:
                self.assertNotIn("matcher", group, event)
            self.assertEqual(len(group["hooks"]), 1, event)
            h = group["hooks"][0]
            expected = {"type": "command", "command": HOOK_PATH, "timeout": 10}
            if event == "PreToolUse":
                expected["onFailure"] = "block"
            self.assertEqual(h, expected, event)

    def test_jq_validates(self):
        if not shutil.which("jq"):
            self.skipTest("jq not installed")
        subprocess.run(["jq", "empty",
                        str(S.AUDIT_DIR / "managed-settings.d/50-agent-audit.json")],
                       check=True)


class SmallFilesTests(unittest.TestCase):

    def test_pam_exactly_two_lines(self):
        self.assertEqual(read("pam.d/agent-run"),
                         "account required pam_permit.so\n"
                         "session required pam_loginuid.so\n")

    def test_sysctl(self):
        lines = [line for line in read("sysctl.d/60-agent-ptrace.conf").splitlines()
                 if line.strip() and not line.startswith("#")]
        self.assertEqual(lines, ["kernel.yama.ptrace_scope = 1"])


# -----------------------------------------------------------------
# audit.rules lint: a small parser for exactly the auditctl grammar we use.
# -----------------------------------------------------------------

AUDIT_KEYS = {"agent-exec", "agent-socket", "agent-secret-read", "agent-policy"}
SYSCALLS = {"execve", "execveat", "socket"}
UID_VALUE = r"(@AGENT_UID@|[0-9]+)"
FIELD_RES = {
    "arch": r"b64|b32",
    "uid": UID_VALUE,
    "a0": r"[0-9]+",
}


def lint_rule(line):
    """Return an error string for one rules line, or None if valid."""
    if not line.strip() or line.startswith("#"):
        return None
    tokens = line.split()
    if tokens[0] == "-b":
        if len(tokens) == 2 and tokens[1].isdigit():
            return None
        return "bad -b"
    if tokens[0] == "-w":
        # -w PATH -p PERMS -k KEY
        if len(tokens) != 6 or tokens[2] != "-p" or tokens[4] != "-k":
            return "watch must be: -w PATH -p PERMS -k KEY"
        path = tokens[1].replace("@AGENT_HOME@", "/home/agent", 1)
        if not path.startswith("/") or ".." in path:
            return "watch path must be absolute"
        if not re.fullmatch(r"[rwxa]+", tokens[3]):
            return "bad permissions"
        if tokens[5] not in AUDIT_KEYS:
            return f"unknown key {tokens[5]}"
        return None
    if tokens[0] == "-a":
        if len(tokens) < 2 or tokens[1] != "always,exit":
            return "only -a always,exit is used"
        rest = tokens[2:]
        if len(rest) % 2:
            return "dangling option"
        pairs = list(zip(rest[0::2], rest[1::2]))
        seen_arch = seen_syscall = False
        key = None
        for opt, val in pairs:
            if key is not None:
                return "-k must be last"
            if opt == "-F":
                name, sep, value = val.partition("=")
                if not sep or name not in FIELD_RES:
                    return f"unknown field {val}"
                if not re.fullmatch(FIELD_RES[name], value):
                    return f"bad value in {val}"
                if name == "arch":
                    if seen_syscall:
                        return "arch must precede -S"
                    seen_arch = True
            elif opt == "-S":
                if not seen_arch:
                    return "-S without a preceding arch"
                names = val.split(",")
                if not names or not set(names) <= SYSCALLS:
                    return f"unknown syscall in {val}"
                seen_syscall = True
            elif opt == "-k":
                if val not in AUDIT_KEYS:
                    return f"unknown key {val}"
                key = val
            else:
                return f"unknown option {opt}"
        if not seen_syscall:
            return "syscall rule without -S"
        if key is None:
            return "rule without -k"
        if "uid" not in [v.partition("=")[0] for o, v in pairs if o == "-F"]:
            return "agent rule without uid filter"
        return None
    return f"unknown directive {tokens[0]}"


class AuditRulesTests(unittest.TestCase):

    def rules(self):
        return read("audit.rules").splitlines()

    def test_every_line_parses(self):
        for n, line in enumerate(self.rules(), 1):
            self.assertIsNone(lint_rule(line), f"line {n}: {line}")

    def test_linter_rejects_bad_lines(self):
        for bad in ("-a always,exit -S execve -F arch=b64 -F uid=1 -k agent-exec",
                    "-a always,exit -F arch=b64 -S execve -k agent-exec",
                    "-a always,exit -F arch=b64 -S execve -F uid=1",
                    "-a never,exit -F arch=b64 -S execve -F uid=1 -k agent-exec",
                    "-w etc/foo -p wa -k agent-policy",
                    "-w /etc/foo -p q -k agent-policy",
                    "-w /etc/foo -p wa -k other",
                    "-D", "-e 2"):
            self.assertIsNotNone(lint_rule(bad), bad)

    def test_matches_design_doc(self):
        # The rule lines must be the ones in implementation.md ("Kernel audit rules").
        doc = (S.REPO / "docs/design/implementation.md").read_text()
        block = re.search(r"^## Kernel audit rules\n.*?```\n(.*?)```", doc, re.S | re.M)
        self.assertIsNotNone(block)

        def rule_lines(lines):
            return [line for line in lines if line.strip() and not line.startswith("#")]
        self.assertEqual(rule_lines(self.rules()),
                         rule_lines(block.group(1).splitlines()))

    def test_template_placeholder(self):
        text = "\n".join(line for line in self.rules()
                          if not line.startswith("#"))
        self.assertEqual(text.count("@AGENT_UID@"), 6)
        self.assertEqual(text.count("@AGENT_HOME@"), 2)
        self.assertNotRegex(text, r"uid=[0-9]")


class ShellScriptTests(unittest.TestCase):
    SCRIPTS = ["agent-run", "install.sh", "install-claude.sh"]

    def test_bash_syntax(self):
        for name in self.SCRIPTS:
            subprocess.run(["bash", "-n", str(S.AUDIT_DIR / name)], check=True)

    def test_executable_and_strict(self):
        for name in self.SCRIPTS:
            path = S.AUDIT_DIR / name
            self.assertTrue(os.access(path, os.X_OK), name)
            self.assertIn("set -euo pipefail", path.read_text(), name)

    def test_shellcheck(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck not installed")
        subprocess.run(["shellcheck", *[str(S.AUDIT_DIR / n) for n in self.SCRIPTS]],
                       check=True)


if __name__ == "__main__":
    unittest.main()
