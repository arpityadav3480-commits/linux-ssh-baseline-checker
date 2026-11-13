"""Tests for baseline_checker.py. Run with: python -m unittest discover -v -s tests"""
import ast
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import baseline_checker as bc  # noqa: E402

FIXTURES = ROOT / "fixtures"
BAD = FIXTURES / "sshd_config_sample.txt"
GOOD = FIXTURES / "sshd_config_hardened_reference.txt"
POLICY = ROOT / "baseline" / "lab_policy.json"
UBUNTU = FIXTURES / "os_release_ubuntu_2404.txt"
UNSUPPORTED = FIXTURES / "os_release_unsupported.txt"

SSHD_T_OUTPUT = """port 22
permitrootlogin no
passwordauthentication no
permitemptypasswords no
x11forwarding no
maxauthtries 4
clientaliveinterval 300
allowusers trainee-admin
"""


def run_cli(*args):
    """Return (exit code, stdout, stderr) from the checker."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = bc.main(list(args))
    return code, out.getvalue(), err.getvalue()


def statuses(*args):
    """Return (exit code, {check id: status}) from a JSON run."""
    code, out, _ = run_cli(*args, "--format", "json")
    return code, {f["id"]: f["status"] for f in json.loads(out)["findings"]}


class ConfigFileCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def write(self, text, name="sshd_config"):
        path = self.tmp / name
        path.write_text(text, encoding="utf-8")
        return str(path)


class TestKnownStates(ConfigFileCase):
    def test_t01_known_good_with_policy_all_pass(self):
        code, result = statuses("--config", str(GOOD), "--policy", str(POLICY))
        self.assertEqual(code, bc.EXIT_CLEAN)
        self.assertEqual(set(result.values()), {bc.PASS})
        self.assertEqual(len(result), 7)

    def test_t02_known_bad_without_policy_separates_definite_from_policy(self):
        code, result = statuses("--config", str(BAD))
        self.assertEqual(code, bc.EXIT_FINDINGS)
        self.assertEqual(result, {"LIN-01": bc.FAIL, "LIN-02": bc.REVIEW, "LIN-03": bc.PASS,
                                  "LIN-04": bc.REVIEW, "LIN-05": bc.REVIEW, "LIN-06": bc.REVIEW,
                                  "LIN-07": bc.REVIEW})

    def test_t03_known_bad_with_policy_turns_reviews_into_fails(self):
        code, result = statuses("--config", str(BAD), "--policy", str(POLICY))
        self.assertEqual(code, bc.EXIT_FINDINGS)
        self.assertEqual(result.pop("LIN-03"), bc.PASS)
        self.assertEqual(set(result.values()), {bc.FAIL})

    def test_t04_known_good_without_policy_still_needs_review_of_approved_values(self):
        code, result = statuses("--config", str(GOOD))
        self.assertEqual(code, bc.EXIT_FINDINGS)
        self.assertEqual(result["LIN-06"], bc.REVIEW)
        self.assertEqual(result["LIN-07"], bc.REVIEW)
        self.assertEqual(sum(s == bc.PASS for s in result.values()), 5)

    def test_t05_one_config_change_is_detected_and_retest_after_fix_passes(self):
        good = GOOD.read_text(encoding="utf-8")
        broken = self.write(good.replace("PermitRootLogin no", "PermitRootLogin yes"))
        code, result = statuses("--config", broken, "--policy", str(POLICY))
        self.assertEqual(code, bc.EXIT_FINDINGS)
        self.assertEqual(result["LIN-01"], bc.FAIL)
        self.assertEqual(sum(s == bc.FAIL for s in result.values()), 1)
        fixed = self.write(good, "fixed")
        code, result = statuses("--config", fixed, "--policy", str(POLICY))
        self.assertEqual((code, result["LIN-01"]), (bc.EXIT_CLEAN, bc.PASS))

    def test_t06_baseline_agrees_with_starter_pack(self):
        starter = json.loads((FIXTURES / "linux_baseline.json").read_text(encoding="utf-8"))
        ours = bc.load_baseline(bc.DEFAULT_BASELINE)
        self.assertEqual([(c["id"], c["setting"]) for c in starter["checks"]],
                         [(c["id"], c["setting"]) for c in ours["checks"]])
        settings, _ = bc.parse_config(BAD.read_text(encoding="utf-8"))
        for check in starter["checks"]:
            self.assertEqual(settings[check["setting"].lower()][0][2], check["observed"])


class TestSshdRules(ConfigFileCase):
    def test_t07_first_value_wins_and_keywords_ignore_case(self):
        path = self.write("permitrootlogin no\nPermitRootLogin yes\n")
        _, result = statuses("--config", path)
        self.assertEqual(result["LIN-01"], bc.PASS)

    def test_t08_match_block_does_not_change_global_result(self):
        path = self.write("PermitRootLogin no\nMatch User bob\n  PermitRootLogin yes\n")
        code, out, _ = run_cli("--config", path)
        self.assertEqual(code, bc.EXIT_FINDINGS)
        self.assertIn("Match block found", out)
        self.assertIn("PASS    LIN-01", out)

    def test_t09_include_is_reported_not_silently_ignored(self):
        _, out, _ = run_cli("--config", self.write("Include /etc/ssh/sshd_config.d/*.conf\n"))
        self.assertIn("Include was not followed", out)

    def test_t10_missing_setting_uses_documented_default_and_says_so(self):
        code, out, _ = run_cli("--config", self.write("Port 22\n"), "--format", "json")
        finding = {f["id"]: f for f in json.loads(out)["findings"]}["LIN-01"]
        self.assertEqual(code, bc.EXIT_FINDINGS)
        self.assertEqual((finding["status"], finding["observed"]), (bc.FAIL, "prohibit-password"))
        self.assertIn("documented default", finding["evidence"])

    def test_t11_time_values_convert_to_seconds(self):
        path = self.write("ClientAliveInterval 5m\n")
        _, result = statuses("--config", path, "--policy", str(POLICY))
        self.assertEqual(result["LIN-06"], bc.PASS)

    def test_t12_allowusers_lines_add_up_and_unapproved_account_fails(self):
        path = self.write("AllowUsers trainee-admin\nAllowUsers intruder\n")
        _, result = statuses("--config", path, "--policy", str(POLICY))
        self.assertEqual(result["LIN-07"], bc.FAIL)

    def test_t13_invalid_value_is_unknown_never_pass(self):
        path = self.write("MaxAuthTries lots\n")
        _, result = statuses("--config", path)
        self.assertEqual(result["LIN-05"], bc.UNKNOWN)

    def test_t14_only_unknown_results_do_not_exit_clean(self):
        path = self.write("PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n"
                          "X11Forwarding no\nMaxAuthTries lots\nClientAliveInterval 300\n"
                          "AllowUsers trainee-admin\n")
        code, _ = statuses("--config", path, "--policy", str(POLICY))
        self.assertEqual(code, bc.EXIT_CANNOT_AUDIT)


class TestFailsSafely(ConfigFileCase):
    def assert_cannot_audit(self, *args, message=""):
        code, out, err = run_cli(*args)
        self.assertEqual(code, bc.EXIT_CANNOT_AUDIT)
        self.assertEqual(out, "", "a failed audit must not print a report")
        self.assertIn(message, err)

    def test_t15_missing_config_file(self):
        self.assert_cannot_audit("--config", str(self.tmp / "absent"), message="cannot read config file")

    def test_t16_binary_config_file(self):
        path = self.tmp / "binary"
        path.write_bytes(b"\xff\xfe\x00\x80")
        self.assert_cannot_audit("--config", str(path), message="not a UTF-8 text file")

    def test_t17_policy_cannot_override_a_definite_check(self):
        policy = self.write('{"PermitRootLogin": ["yes"]}', "policy.json")
        self.assert_cannot_audit("--config", str(BAD), "--policy", policy, message="not a policy-based check")

    def test_t18_corrupt_baseline(self):
        self.assert_cannot_audit("--config", str(BAD), "--baseline", self.write("{oops", "b.json"),
                                 message="not valid JSON")

    def test_t19_check_without_citation_is_rejected(self):
        baseline = json.loads(bc.DEFAULT_BASELINE.read_text(encoding="utf-8"))
        baseline["checks"][0]["references"] = []
        path = self.write(json.dumps(baseline), "b.json")
        self.assert_cannot_audit("--config", str(BAD), "--baseline", path, message="has no citation")


class TestLiveMode(unittest.TestCase):
    def assert_live_cannot_audit(self, os_release, message):
        code, out, err = run_cli("--live", "--os-release", str(os_release))
        self.assertEqual(code, bc.EXIT_CANNOT_AUDIT)
        self.assertEqual(out, "")
        self.assertIn(message, err)

    def test_t20_unsupported_os_stops_before_running_anything(self):
        with mock.patch.object(bc.subprocess, "run") as run:
            self.assert_live_cannot_audit(UNSUPPORTED, "unsupported OS")
        run.assert_not_called()

    def test_t21_missing_os_release(self):
        self.assert_live_cannot_audit(FIXTURES / "absent", "cannot read OS release file")

    @mock.patch.object(bc, "SSHD_FALLBACK", Path("/nonexistent/sshd"))
    @mock.patch.object(bc.shutil, "which", return_value=None)
    def test_t22_missing_sshd_command(self, _which):
        self.assert_live_cannot_audit(UBUNTU, "sshd was not found")

    @mock.patch.object(bc.shutil, "which", return_value="/usr/sbin/sshd")
    @mock.patch.object(bc.subprocess, "run")
    def test_t23_sshd_permission_failure_suggests_sudo(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 255, "", "Permission denied")
        self.assert_live_cannot_audit(UBUNTU, "never elevates itself")

    @mock.patch.object(bc.shutil, "which", return_value="/usr/sbin/sshd")
    @mock.patch.object(bc.subprocess, "run", side_effect=subprocess.TimeoutExpired("sshd", 15))
    def test_t24_sshd_timeout(self, _run, _which):
        self.assert_live_cannot_audit(UBUNTU, "did not finish")

    @mock.patch.object(bc.shutil, "which", return_value="/usr/sbin/sshd")
    @mock.patch.object(bc.subprocess, "run")
    def test_t25_live_success_runs_only_sshd_test_mode(self, run, _which):
        run.return_value = subprocess.CompletedProcess([], 0, SSHD_T_OUTPUT, "")
        code, out, _ = run_cli("--live", "--os-release", str(UBUNTU), "--policy", str(POLICY))
        self.assertEqual(code, bc.EXIT_CLEAN)
        self.assertIn("sshd -T", out)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["/usr/sbin/sshd", "-T"])
        self.assertNotIn("shell", run.call_args.kwargs)


class TestReadOnlyAndReports(unittest.TestCase):
    def test_t26_inputs_are_unchanged_after_a_run(self):
        paths = [BAD, GOOD, POLICY, bc.DEFAULT_BASELINE]
        digest = lambda: [hashlib.sha256(p.read_bytes()).hexdigest() for p in paths]  # noqa: E731
        before = digest()
        run_cli("--config", str(BAD), "--policy", str(POLICY))
        self.assertEqual(digest(), before)

    def test_t27_source_has_no_way_to_write_or_change_the_system(self):
        tree = ast.parse((ROOT / "baseline_checker.py").read_text(encoding="utf-8"))
        banned = {"open", "write_text", "write_bytes", "unlink", "rename", "mkdir", "rmdir", "touch",
                  "chmod", "chown", "remove", "system", "popen", "Popen", "move", "rmtree", "copy"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "attr", getattr(node.func, "id", ""))
                self.assertNotIn(name, banned, f"banned call on line {node.lineno}")

    def test_t28_all_report_formats_include_evidence_and_sources(self):
        for fmt in ("text", "markdown", "json"):
            code, out, _ = run_cli("--config", str(BAD), "--format", fmt)
            self.assertEqual(code, bc.EXIT_FINDINGS)
            self.assertIn("PermitRootLogin yes", out)
            self.assertIn("5.1.20", out)
            self.assertIn("manpages.ubuntu.com", out)


if __name__ == "__main__":
    unittest.main()
