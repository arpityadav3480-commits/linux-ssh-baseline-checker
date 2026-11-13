"""Check that the test suite can fail: add one bug at a time to a temporary copy.

Usage:  python tools/mutation_check.py
Exits with 1 if any bug is missed.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (bug description, original code, code with the bug)
BUGS = [
    ("definite treated as review", 'if check["basis"] == "definite":\n        return FAIL',
     'if check["basis"] == "definite":\n        return REVIEW'),
    ("no policy means pass", "if approved is None:\n        return REVIEW", "if approved is None:\n        return PASS"),
    ("last value wins", "number, line, value = entries[0]", "number, line, value = entries[-1]"),
    ("invalid value means pass", "if value is None:\n        return UNKNOWN", "if value is None:\n        return PASS"),
    ("unknown exits clean", "return EXIT_CANNOT_AUDIT if summary[UNKNOWN] else EXIT_CLEAN", "return EXIT_CLEAN"),
    ("match block ignored", 'if keyword == "match":', 'if keyword == "matchX":'),
    ("os check skipped", 'check_supported_os(args.os_release, baseline["supported_os"])', "pass"),
    ("policy can override definite", "if setting not in policy_settings:", "if False:"),
    ("citations optional", 'if not check.get("references"):', "if False:"),
    ("adds shell=True", "timeout=SSHD_TIMEOUT_SECONDS, check=False)",
     "timeout=SSHD_TIMEOUT_SECONDS, check=False, shell=True)"),
    ("ignores sshd failure", "if result.returncode != 0:", "if False:"),
    ("time units ignored", "int(n) * TIME_UNITS[unit.lower()]", "int(n)"),
    ("writes a file", "print(FORMATTERS[args.format](report))",
     'print(FORMATTERS[args.format](report)); Path("x").write_text("x")'),
]


def main():
    source = (ROOT / "baseline_checker.py").read_text(encoding="utf-8")
    missed = 0
    for name, original, buggy in BUGS:
        if original not in source:
            print(f"ERROR: code for '{name}' was not found; update this script")
            return 1
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for folder in ("baseline", "fixtures", "tests"):
                shutil.copytree(ROOT / folder, work / folder, ignore=shutil.ignore_patterns("__pycache__"))
            (work / "baseline_checker.py").write_text(source.replace(original, buggy), encoding="utf-8")
            result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                                    cwd=work, capture_output=True, text=True, check=False)
        caught = result.returncode != 0
        missed += not caught
        print(f"{'CAUGHT' if caught else 'MISSED'}  {name}")
    print(f"Missed: {missed} of {len(BUGS)}")
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main())
