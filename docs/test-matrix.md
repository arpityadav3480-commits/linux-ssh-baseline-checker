# Test Matrix

## Automated tests

**Run on:** 30 October 2026, Windows 11, Python 3.13. **Result:** 28 of 28 passed. Raw output: [unit-test-output.txt](../evidence/unit-test-output.txt).

T20 to T25 use a simulated `sshd`, so they test the tool's logic, not real SSH behaviour. The V tests below cover that.

| ID | Type | Scenario | Expected | Actual |
|---|---|---|---|---|
| T01 | Should pass | Hardened config with lab policy | All 7 PASS, exit 0 | As expected |
| T02 | Known bad | Weak config, no policy | LIN-01 FAIL, LIN-03 PASS, other 5 REVIEW, exit 1 | As expected |
| T03 | Known bad | Weak config with lab policy | 6 FAIL, LIN-03 PASS, exit 1 | As expected |
| T04 | Policy logic | Hardened config, no policy | 5 PASS, LIN-06 and LIN-07 REVIEW, exit 1 | As expected |
| T05 | Variation and retest | Change one setting, then restore it | LIN-01 is the only FAIL, then all PASS | As expected |
| T06 | Data check | Compare with starter baseline | Same IDs and settings; observed values match the sample | As expected |
| T07 | sshd rules | Repeated keyword, mixed case | First value used | As expected |
| T08 | Edge case | `Match` block | Override ignored and noted | As expected |
| T09 | Edge case | `Include` line | Reported in notes | As expected |
| T10 | Edge case | Setting not present | Documented default used and stated | As expected |
| T11 | Edge case | `ClientAliveInterval 5m` | Read as 300 seconds | As expected |
| T12 | Edge case | Two `AllowUsers` lines, one unapproved | LIN-07 FAIL | As expected |
| T13 | Bad input | `MaxAuthTries lots` | UNKNOWN, never PASS | As expected |
| T14 | Fails safely | Only UNKNOWN results remain | Exit 3, not exit 0 | As expected |
| T15 | Missing file | Config file absent | Exit 3, no report | As expected |
| T16 | Bad input | Binary config file | Exit 3, no report | As expected |
| T17 | Safety | Policy tries to approve `PermitRootLogin yes` | Rejected, exit 3 | As expected |
| T18 | Bad input | Corrupt baseline JSON | Exit 3, no report | As expected |
| T19 | Safety | Baseline check with no citation | Rejected, exit 3 | As expected |
| T20 | Unsupported OS | Fake OS file | Exit 3, `sshd` never run | As expected |
| T21 | Missing file | No OS release file | Exit 3 | As expected |
| T22 | Missing command | No `sshd` installed | Exit 3 | As expected |
| T23 | Permissions | `sshd -T` refused | Exit 3, suggests sudo | As expected |
| T24 | Fails safely | `sshd -T` hangs | Exit 3 | As expected |
| T25 | Safety | Live run succeeds | Runs exactly `sshd -T`, with no shell | As expected |
| T26 | Read-only | Hash inputs before and after | Unchanged | As expected |
| T27 | Read-only | Scan source for write or change calls | None found | As expected |
| T28 | Reports | Text, Markdown and JSON | All show evidence and sources | As expected |

## Do the tests catch bugs?

**Result:** all 13 deliberate bugs were caught. Raw output: [mutation-check-output.txt](../evidence/mutation-check-output.txt). This shows the tests can fail, not that the tool has no bugs.

## Real VM tests

**Run on:** 13 November 2026, Ubuntu 24.04.5 LTS in VirtualBox (kernel 6.8.0-149, OpenSSH 1:9.6p1-3ubuntu13.20, Python 3.12.3), with the lab policy. **Result:** 6 of 6 as expected. Raw output: [evidence/vm/](../evidence/vm/). The VM's versions and the hashes of the tool files copied into it are in [v0-environment.txt](../evidence/vm/v0-environment.txt); they match the repository copy. Steps are in [vm-lab-guide.md](vm-lab-guide.md).

| ID | Scenario | Expected | Actual | Evidence |
|---|---|---|---|---|
| V1 | Fresh Ubuntu 24.04 | LIN-01 FAIL, exit 1 | As expected. LIN-01 FAIL on `without-password` (how `sshd -T` prints the default `prohibit-password`). LIN-02 and LIN-04 to LIN-07 also FAIL under the lab policy; LIN-03 PASS | [v1-fresh-install.md](../evidence/vm/v1-fresh-install.md), [v1-exit.txt](../evidence/vm/v1-exit.txt) |
| V2 | Hash `/etc/ssh` before and after a run | Unchanged | As expected. All 11 files unchanged | [v2-read-only.txt](../evidence/vm/v2-read-only.txt) |
| V3 | Apply fix by hand, then retest | All 7 PASS, exit 0 | As expected | [v3-after-fix.md](../evidence/vm/v3-after-fix.md), [v3-exit.txt](../evidence/vm/v3-exit.txt) |
| V4 | Weak drop-in overrides the fix | Only LIN-01 FAIL, exit 1 | As expected. Evidence line: `permitrootlogin yes` | [v4-detect-change.md](../evidence/vm/v4-detect-change.md), [v4-exit.txt](../evidence/vm/v4-exit.txt) |
| V5 | Remove the weak drop-in | All 7 PASS, exit 0 | As expected | [v5-after-rollback.md](../evidence/vm/v5-after-rollback.md), [v5-exit.txt](../evidence/vm/v5-exit.txt) |
| V6 | Run live mode without sudo | Clear error, exit 3 | As expected. `sshd -T` could not read `50-cloud-init.conf`, and the tool suggested sudo | [v6-no-sudo.txt](../evidence/vm/v6-no-sudo.txt) |

### What the VM showed

- **The installer adds a drop-in.** Allowing password login during installation creates `/etc/ssh/sshd_config.d/50-cloud-init.conf` containing `PasswordAuthentication yes`. That is why LIN-02 failed in V1. In V3, `10-lab-hardened.conf` loads first, so its `no` wins. This is the first-value-wins rule working on a real host, not only in the simulated tests.
- **`sshd -T` prints an alias.** It shows the default as `without-password`, not `prohibit-password`. The tool treated it as FAIL, which is correct, because only `no` passes.
- **Why non-root fails here.** `50-cloud-init.conf` is mode 0600, so a normal user's `sshd -T` stops at that file. A host without such a file may fail differently, but the tool exits 3 either way.
