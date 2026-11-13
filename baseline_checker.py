#!/usr/bin/env python3
"""Read-only Linux security baseline checker for SSH server settings.

Compares SSH settings with a cited baseline and reports the evidence, risk and
a suggested fix for each check. It never changes the system: it reads files,
runs `sshd -T` in live mode, and writes its report to stdout only.

Usage:
  python3 baseline_checker.py --config fixtures/sshd_config_sample.txt
  python3 baseline_checker.py --config FILE --policy baseline/lab_policy.json
  sudo python3 baseline_checker.py --live --format markdown

Exit codes:
  0  every check passed
  1  at least one FAIL or REVIEW
  2  bad command-line arguments
  3  the audit could not be completed, so nothing should be assumed safe
"""
import argparse
import json
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_BASELINE = Path(__file__).resolve().parent / "baseline" / "ssh_baseline.json"
SSHD_FALLBACK = Path("/usr/sbin/sshd")
SSHD_TIMEOUT_SECONDS = 15

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_CANNOT_AUDIT = 3

PASS, FAIL, REVIEW, UNKNOWN = "PASS", "FAIL", "REVIEW", "UNKNOWN"
TIME_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


class AuditError(Exception):
    """The audit cannot be completed, so no results should be reported."""


def read_text(path, description):
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as err:
        raise AuditError(f"cannot read {description} '{path}': {err.strerror or err}") from err
    except UnicodeDecodeError as err:
        raise AuditError(f"{description} '{path}' is not a UTF-8 text file") from err


def read_json(path, description):
    try:
        return json.loads(read_text(path, description))
    except json.JSONDecodeError as err:
        raise AuditError(f"{description} '{path}' is not valid JSON: {err}") from err


def load_baseline(path):
    baseline = read_json(path, "baseline")
    try:
        references = baseline["references"]
        for check in baseline["checks"]:
            for field in ("id", "setting", "basis", "severity", "value_type", "default",
                          "expected", "rationale", "remediation"):
                if not check.get(field):
                    raise AuditError(f"baseline check is missing '{field}': {check.get('id', check)}")
            if not check.get("references"):
                raise AuditError(f"baseline check {check['id']} has no citation")
            for ref in check["references"]:
                if ref["source"] not in references:
                    raise AuditError(f"baseline check {check['id']} cites unknown source '{ref['source']}'")
    except (KeyError, TypeError) as err:
        raise AuditError(f"baseline '{path}' has the wrong structure: {err}") from err
    return baseline


def load_policy(path, baseline):
    """Return {setting: {approved values}}. Policy can only decide policy-based checks."""
    if path is None:
        return {}
    policy = read_json(path, "policy")
    if not isinstance(policy, dict):
        raise AuditError(f"policy '{path}' must be a JSON object")
    policy_settings = {c["setting"] for c in baseline["checks"] if c["basis"] == "policy"}
    for setting, approved in policy.items():
        if setting not in policy_settings:
            raise AuditError(f"policy cannot decide '{setting}': not a policy-based check")
        if not isinstance(approved, list) or not approved:
            raise AuditError(f"policy value for '{setting}' must be a non-empty list")
    return {setting: {str(value) for value in approved} for setting, approved in policy.items()}


def parse_config(text):
    """Parse sshd_config text or `sshd -T` output.

    Returns ({lowercase keyword: [(line number, line, value), ...]}, notes).
    Keywords are case-insensitive, and only the global section is read because
    Match blocks apply to particular connections.
    """
    settings, notes = {}, []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"(\S+?)(?:\s*=\s*|\s+)(.*)$", line)
        keyword, value = (match.group(1), match.group(2)) if match else (line, "")
        keyword = keyword.lower()
        if keyword == "match":
            notes.append(f"Line {number}: Match block found. Its overrides were not evaluated.")
            break
        if keyword == "include":
            notes.append(f"Line {number}: Include was not followed, so settings in those files "
                         "are missing. Use --live to see the effective configuration.")
            continue
        value = re.sub(r"\s+#.*$", "", value).strip().strip('"')
        settings.setdefault(keyword, []).append((number, line, value))
    return settings, notes


def resolve(check, settings, source_label):
    """Return (raw value, evidence) for a check, applying sshd's rules."""
    entries = settings.get(check["setting"].lower())
    if not entries:
        return check["default"], f"Not set in {source_label}; documented default is '{check['default']}'"
    if check["value_type"] == "accounts":  # repeated AllowUsers lines add up
        value = " ".join(entry[2] for entry in entries)
        evidence = "; ".join(f"line {entry[0]}: {entry[1]}" for entry in entries)
        return value, f"{source_label}, {evidence}"
    number, line, value = entries[0]  # sshd uses the first value it finds
    evidence = f"{source_label}, line {number}: {line}"
    if len(entries) > 1:
        evidence += f" (first of {len(entries)} lines; sshd uses the first)"
    return value, evidence


def normalise(check, raw):
    """Return a comparable value, or None if sshd's rules do not allow it."""
    kind = check["value_type"]
    if kind == "choice":
        value = raw.lower()
        return value if value in check["choices"] else None
    if kind == "int":
        return raw if re.fullmatch(r"\d+", raw) else None
    if kind == "time":
        if not re.fullmatch(r"(\d+[smhdwSMHDW]?)+", raw):
            return None
        parts = re.findall(r"(\d+)([smhdwSMHDW]?)", raw)
        return str(sum(int(n) * TIME_UNITS[unit.lower()] for n, unit in parts))
    return raw if raw.split() else None  # accounts


def evaluate(check, raw, policy):
    value = normalise(check, raw)
    if value is None:
        return UNKNOWN
    if value in check.get("accepted", []):
        return PASS
    if "accepted_max" in check and int(value) <= check["accepted_max"]:
        return PASS
    if check["basis"] == "definite":
        return FAIL
    approved = policy.get(check["setting"])
    if approved is None:
        return REVIEW
    return PASS if set(value.split()) <= approved else FAIL


def audit(baseline, settings, policy, source_label):
    findings = []
    for check in baseline["checks"]:
        raw, evidence = resolve(check, settings, source_label)
        status = evaluate(check, raw, policy)
        findings.append({
            "id": check["id"],
            "setting": check["setting"],
            "status": status,
            "basis": check["basis"],
            "severity": None if status == PASS else check["severity"],
            "observed": raw,
            "expected": check["expected"],
            "evidence": evidence,
            "rationale": check["rationale"],
            "remediation": None if status == PASS else check["remediation"],
            "references": [
                {**baseline["references"][ref["source"]], "detail": ref["detail"]}
                for ref in check["references"]
            ],
        })
    return findings


def check_supported_os(path, supported):
    fields = {}
    for line in read_text(path, "OS release file").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            fields[key.strip()] = value.strip().strip('"')
    os_id, version = fields.get("ID", "unknown"), fields.get("VERSION_ID", "unknown")
    if version not in supported.get(os_id, []):
        raise AuditError(f"unsupported OS '{os_id} {version}'; live mode supports {supported}. "
                         "Use --config to review a saved file instead.")


def read_live_config():
    """Run `sshd -T`, which prints the effective configuration and exits."""
    sshd = shutil.which("sshd") or (str(SSHD_FALLBACK) if SSHD_FALLBACK.exists() else None)
    if sshd is None:
        raise AuditError("sshd was not found, so the live configuration cannot be read")
    try:
        result = subprocess.run([sshd, "-T"], capture_output=True, text=True,
                                timeout=SSHD_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired as err:
        raise AuditError(f"sshd -T did not finish within {SSHD_TIMEOUT_SECONDS} seconds") from err
    except OSError as err:
        raise AuditError(f"could not run sshd -T: {err}") from err
    if result.returncode != 0:
        detail = result.stderr.strip() or "no error text"
        raise AuditError(f"sshd -T failed ({detail}). It usually needs root; this tool never "
                         "elevates itself, so rerun it with sudo in your lab VM.")
    if not result.stdout.strip():
        raise AuditError("sshd -T returned no configuration")
    return result.stdout


def summarise(findings):
    return {status: sum(f["status"] == status for f in findings)
            for status in (PASS, FAIL, REVIEW, UNKNOWN)}


def format_json(report):
    return json.dumps(report, indent=2)


def format_text(report):
    lines = [f"Baseline: {report['baseline']}", f"Source:   {report['source']}",
             f"Host:     {report['host']}", f"Policy:   {report['policy']}", ""]
    for f in report["findings"]:
        severity = f" [{f['severity']}]" if f["severity"] else ""
        lines.append(f"{f['status']:<8}{f['id']}  {f['setting']} = {f['observed']}{severity}")
        lines.append(f"        Evidence: {f['evidence']}")
        lines.append(f"        Expected: {f['expected']}")
        if f["status"] != PASS:
            lines.append(f"        Risk:     {f['rationale']}")
            lines.append(f"        Fix:      {f['remediation']}")
        for ref in f["references"]:
            lines.append(f"        Source:   {ref['detail']} ({ref['url']})")
        lines.append("")
    lines.extend(f"NOTE: {note}" for note in report["notes"])
    if report["notes"]:
        lines.append("")
    summary = report["summary"]
    lines.append("Summary: " + ", ".join(f"{count} {status}" for status, count in summary.items()))
    return "\n".join(lines)


def format_markdown(report):
    lines = ["# SSH Baseline Report", "",
             f"- **Baseline:** {report['baseline']}", f"- **Source:** {report['source']}",
             f"- **Host:** {report['host']}", f"- **Policy:** {report['policy']}",
             f"- **Generated:** {report['generated_utc']}", ""]
    summary = report["summary"]
    lines.append("**Summary:** " + ", ".join(f"{count} {status}" for status, count in summary.items()))
    lines.extend(["", "| Check | Setting | Result | Basis | Severity | Observed |", "|---|---|---|---|---|---|"])
    for f in report["findings"]:
        observed = f["observed"].replace("*", "\\*")
        lines.append(f"| {f['id']} | `{f['setting']}` | **{f['status']}** | {f['basis']} "
                     f"| {f['severity'] or '-'} | {observed} |")
    if report["notes"]:
        lines.extend(["", "## Notes", ""])
        lines.extend(f"- {note}" for note in report["notes"])
    lines.extend(["", "## Details", ""])
    for f in report["findings"]:
        lines.extend([f"### {f['id']} {f['setting']}: {f['status']}", "",
                      f"- **Evidence:** `{f['evidence']}`", f"- **Expected:** {f['expected']}"])
        if f["status"] != PASS:
            lines.extend([f"- **Risk:** {f['rationale']}", f"- **Suggested fix:** {f['remediation']}"])
        for ref in f["references"]:
            lines.append(f"- **Source:** {ref['detail']} ([{ref['title']}]({ref['url']}))")
        lines.append("")
    return "\n".join(lines)


FORMATTERS = {"text": format_text, "json": format_json, "markdown": format_markdown}


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Read-only SSH baseline checker.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", metavar="FILE", help="review a saved sshd_config or sshd -T file")
    source.add_argument("--live", action="store_true", help="read this machine's settings with sshd -T")
    parser.add_argument("--policy", metavar="FILE", help="JSON file of policy-approved values")
    parser.add_argument("--baseline", metavar="FILE", default=str(DEFAULT_BASELINE))
    parser.add_argument("--os-release", metavar="FILE", default="/etc/os-release",
                        help="OS details file checked in live mode (default: %(default)s)")
    parser.add_argument("--format", choices=sorted(FORMATTERS), default="text")
    return parser.parse_args(argv)


def run(args):
    baseline = load_baseline(args.baseline)
    policy = load_policy(args.policy, baseline)
    if args.live:
        check_supported_os(args.os_release, baseline["supported_os"])
        text, source, host = read_live_config(), "sshd -T", socket.gethostname()
    else:
        text, source, host = read_text(args.config, "config file"), args.config, "not applicable (file review)"
    settings, notes = parse_config(text)
    findings = audit(baseline, settings, policy, source)
    report = {
        "baseline": f"{baseline['name']} v{baseline['version']}",
        "source": source,
        "host": host,
        "policy": args.policy or "none supplied; policy-based checks report REVIEW unless they meet the recommendation",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": summarise(findings),
        "notes": notes,
        "findings": findings,
    }
    print(FORMATTERS[args.format](report))
    summary = report["summary"]
    if summary[FAIL] or summary[REVIEW]:
        return EXIT_FINDINGS
    return EXIT_CANNOT_AUDIT if summary[UNKNOWN] else EXIT_CLEAN


def main(argv=None):
    args = parse_args(argv)
    try:
        return run(args)
    except AuditError as err:
        print(f"ERROR: {err}", file=sys.stderr)
        return EXIT_CANNOT_AUDIT


if __name__ == "__main__":
    sys.exit(main())
