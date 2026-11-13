# SSH Baseline Report

- **Baseline:** RedKross Task 2 SSH baseline v1.0
- **Source:** fixtures/sshd_config_sample.txt
- **Host:** not applicable (file review)
- **Policy:** none supplied; policy-based checks report REVIEW unless they meet the recommendation
- **Generated:** 2026-10-30 16:16:40 UTC

**Summary:** 1 PASS, 1 FAIL, 5 REVIEW, 0 UNKNOWN

| Check | Setting | Result | Basis | Severity | Observed |
|---|---|---|---|---|---|
| LIN-01 | `PermitRootLogin` | **FAIL** | definite | high | yes |
| LIN-02 | `PasswordAuthentication` | **REVIEW** | policy | medium | yes |
| LIN-03 | `PermitEmptyPasswords` | **PASS** | definite | - | no |
| LIN-04 | `X11Forwarding` | **REVIEW** | policy | low | yes |
| LIN-05 | `MaxAuthTries` | **REVIEW** | policy | medium | 12 |
| LIN-06 | `ClientAliveInterval` | **REVIEW** | policy | low | 0 |
| LIN-07 | `AllowUsers` | **REVIEW** | policy | medium | \* |

## Details

### LIN-01 PermitRootLogin: FAIL

- **Evidence:** `fixtures/sshd_config_sample.txt, line 3: PermitRootLogin yes`
- **Expected:** no
- **Risk:** Root is a known account name with full control of the host. Blocking direct root login forces attackers to guess a username as well, and leaves a record of which named user became root.
- **Suggested fix:** Set 'PermitRootLogin no'. First confirm that a non-root account can log in and use sudo.
- **Source:** Control 5.1.20: Ensure sshd PermitRootLogin is disabled ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** PermitRootLogin: accepted values; default is prohibit-password ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-02 PasswordAuthentication: REVIEW

- **Evidence:** `fixtures/sshd_config_sample.txt, line 4: PasswordAuthentication yes`
- **Expected:** no, or a controlled exception approved by policy
- **Risk:** Passwords can be guessed or reused, while key-based login cannot be brute-forced in the same way. Some organisations still allow passwords with compensating controls, so 'yes' is a policy decision.
- **Suggested fix:** Set 'PasswordAuthentication no' once every user has a working key, or record an approved exception in the policy file.
- **Source:** PasswordAuthentication: default is yes ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))
- **Source:** No control for this setting in the mapped benchmark; recommendation comes from the starter baseline ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))

### LIN-03 PermitEmptyPasswords: PASS

- **Evidence:** `fixtures/sshd_config_sample.txt, line 6: PermitEmptyPasswords no`
- **Expected:** no
- **Source:** Control 5.1.19: Ensure sshd PermitEmptyPasswords is disabled ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** PermitEmptyPasswords: default is no ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-04 X11Forwarding: REVIEW

- **Evidence:** `fixtures/sshd_config_sample.txt, line 7: X11Forwarding yes`
- **Expected:** no, unless policy records that it is required
- **Risk:** The manual warns that X11 forwarding may add exposure to the server and to client displays. Some users need graphical programs over SSH, so 'yes' is a policy decision.
- **Suggested fix:** Set 'X11Forwarding no' if nobody needs it. Ubuntu's shipped sshd_config sets it to yes, so check the file as well as the upstream default.
- **Source:** X11Forwarding: default is no; describes the additional exposure; Debian-based packages ship it set to yes ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))
- **Source:** Related, not identical: control 5.1.8 covers DisableForwarding (Level 2 server, Level 1 workstation) ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))

### LIN-05 MaxAuthTries: REVIEW

- **Evidence:** `fixtures/sshd_config_sample.txt, line 8: MaxAuthTries 12`
- **Expected:** 4 or lower, or a value approved by policy
- **Risk:** This limits authentication attempts per connection, which slows password guessing. A higher value is allowed only if policy approves it.
- **Suggested fix:** Set 'MaxAuthTries 4', or record the approved value in the policy file.
- **Source:** Control 5.1.16: Ensure sshd MaxAuthTries is configured (mapped value 4) ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** MaxAuthTries: default is 6 ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-06 ClientAliveInterval: REVIEW

- **Evidence:** `fixtures/sshd_config_sample.txt, line 9: ClientAliveInterval 0`
- **Expected:** the idle timeout approved by policy, in seconds
- **Risk:** A value of 0 means the server sends no client-alive messages, so it does not detect unresponsive clients. The right timeout depends on the organisation, so the checker needs an approved value to compare against.
- **Suggested fix:** Set an approved value such as 'ClientAliveInterval 300' with 'ClientAliveCountMax 2', and record it in the policy file.
- **Source:** Control 5.1.7: Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured (mapping notes CIS requires values above 0) ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** ClientAliveInterval: default is 0, meaning messages are not sent ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-07 AllowUsers: REVIEW

- **Evidence:** `fixtures/sshd_config_sample.txt, line 10: AllowUsers *`
- **Expected:** an explicit list of accounts approved by policy
- **Risk:** By default every user may log in over SSH, including accounts that never need it. Only the organisation knows which accounts are approved, so the checker needs a policy list to compare against.
- **Suggested fix:** Set 'AllowUsers' to the approved accounts, and confirm your own account is listed before restarting SSH so you are not locked out.
- **Source:** Control 5.1.4: Ensure sshd access is configured ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** AllowUsers: by default, login is allowed for all users ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

