# Linux Security Baseline Reference Checker

**RedKross Research Foundation, Task 2 (Group D: Linux Security & System Defence)**
Arpit Yadav, Intern ID 2415

A read-only tool that compares a machine's SSH server settings with a small, cited baseline, then reports the evidence, the risk and a suggested fix for each check.

**Demo video:** *(link to be added)*

## Why it exists

SSH is often the main way into a Linux server, and small configuration mistakes can expose it. Most hardening advice is a long list with no link between a setting and the reason for it. This tool checks 7 settings, cites a source for each, and shows the exact line that caused each result.

It also separates two kinds of result that a plain pass/fail tool would mix up:

| Result | Meaning |
|---|---|
| `PASS` | The setting meets the baseline or an approved policy value |
| `FAIL` | A definite mismatch, or a value the supplied policy does not approve |
| `REVIEW` | The answer depends on your organisation's policy, and no policy was supplied |
| `UNKNOWN` | The value could not be understood, so it is never treated as safe |

## What it checks

| Check | Setting | Basis | Severity | Passes when |
|---|---|---|---|---|
| LIN-01 | `PermitRootLogin` | Definite | High | `no` |
| LIN-02 | `PasswordAuthentication` | Policy | Medium | `no`, or approved by policy |
| LIN-03 | `PermitEmptyPasswords` | Definite | High | `no` |
| LIN-04 | `X11Forwarding` | Policy | Low | `no`, or approved by policy |
| LIN-05 | `MaxAuthTries` | Policy | Medium | 4 or lower, or approved by policy |
| LIN-06 | `ClientAliveInterval` | Policy | Low | Matches the approved value |
| LIN-07 | `AllowUsers` | Policy | Medium | Every listed account is approved |

The source for each check is in [docs/check-reference-mapping.md](docs/check-reference-mapping.md).

## Setup

**Dependencies:** Python 3.10 or later, with no extra packages. Live mode also needs Ubuntu 24.04 and `openssh-server`.

```bash
git clone <repository-url>
cd <repository-folder>
python3 baseline_checker.py --help
```

See [docs/supported-os.md](docs/supported-os.md) for what has been tested. To run live mode safely, follow [docs/vm-lab-guide.md](docs/vm-lab-guide.md).

## Usage

```bash
# Review a saved config file (works on any OS)
python3 baseline_checker.py --config fixtures/sshd_config_sample.txt

# Add a policy so REVIEW results become PASS or FAIL
python3 baseline_checker.py --config fixtures/sshd_config_sample.txt --policy baseline/lab_policy.json

# Check the machine you are on (disposable lab VM only; sudo is usually needed to run sshd -T)
sudo python3 baseline_checker.py --live --policy baseline/lab_policy.json

# Choose a report format: text (default), markdown or json
python3 baseline_checker.py --config fixtures/sshd_config_sample.txt --format markdown
```

Example output:

```text
FAIL    LIN-01  PermitRootLogin = yes [high]
        Evidence: fixtures/sshd_config_sample.txt, line 3: PermitRootLogin yes
        Expected: no
```

Sample reports are in [reports/](reports/).

| Exit code | Meaning |
|---|---|
| 0 | Every check passed |
| 1 | At least one `FAIL` or `REVIEW` |
| 2 | Bad command-line arguments |
| 3 | The audit could not be completed, so nothing should be assumed safe |

## How it works

1. **Load** the baseline and reject any check without a citation. Load the optional policy, which can only decide policy-based checks, so it can never approve `PermitRootLogin yes`.
2. **Read** a saved file, or in live mode run `sshd -T`, which prints the settings actually in effect.
3. **Apply sshd's rules:** keywords ignore case, the first value wins, and `AllowUsers` lines add up. `Match` overrides are noted but not evaluated.
4. **Evaluate** each check and print the report to stdout.

Live mode matters because Ubuntu includes `/etc/ssh/sshd_config.d/*.conf` at the top of the main file, and those values override the ones below them. Reading only `sshd_config` can give the wrong answer.

## Testing

```bash
python3 -m unittest discover -v -s tests
python3 tools/mutation_check.py
```

- [docs/test-matrix.md](docs/test-matrix.md) lists each test with expected and actual results.
- [evidence/](evidence/) holds the raw output. [evidence/vm/](evidence/vm/) holds the live-mode results from a real Ubuntu 24.04.5 VM.
- `tools/mutation_check.py` adds deliberate bugs to a temporary copy and confirms the tests catch them.

## Safety and scope

- **Read-only.** The tool never changes the system and writes only to stdout. It never runs `sudo` by itself.
- **Lab use only.** Run live mode only on a machine you own or are authorised to audit, ideally a disposable VM. Never change SSH settings on a shared or production server.
- **Test data.** Files in `fixtures/` come from the RedKross starter pack or are synthetic. They contain no real credentials or personal data.
- **Rolling back.** Any change made during testing is made by hand. See [docs/rollback-notes.md](docs/rollback-notes.md).

## Limitations

- It covers 7 SSH settings, not the whole system. A clean result does not mean a host is secure.
- It reads the global SSH configuration only, so `Match` overrides for particular users or hosts are not evaluated.
- In file mode, `Include` is not followed and unset values use the documented default. The report says when this happens.
- CIS citations come from the open ComplianceAsCode mapping of CIS v1.0.0. The CIS PDF itself was not read.
- `lab_policy.json` is an example for the lab, not a recommendation for a real organisation.
- The starter pack's `asset_inventory.csv` is not used. One policy applies to the whole host. A possible improvement is choosing policy values per host from the inventory, for example allowing SSH admin access only where `ssh_admin_required` is `yes`.

## References

Accessed 30 October 2026. See [docs/check-reference-mapping.md](docs/check-reference-mapping.md) for how each one was used.

- [sshd_config(5), Ubuntu 24.04](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html) and [sshd(8), Ubuntu 24.04](https://manpages.ubuntu.com/manpages/noble/man8/sshd.8.html)
- [sshd_config(5), OpenBSD upstream](https://man.openbsd.org/sshd_config)
- [ComplianceAsCode mapping of the CIS Ubuntu 24.04 LTS Benchmark v1.0.0](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml)
- [Ubuntu Server Guide: OpenSSH server](https://documentation.ubuntu.com/server/how-to/security/openssh-server/)
- [Ubuntu Security Guide](https://documentation.ubuntu.com/security/compliance/usg/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
