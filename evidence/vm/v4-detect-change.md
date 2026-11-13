# SSH Baseline Report

- **Baseline:** RedKross Task 2 SSH baseline v1.0
- **Source:** sshd -T
- **Host:** redkross-lab
- **Policy:** baseline/lab_policy.json
- **Generated:** 2026-11-13 07:10:26 UTC

**Summary:** 6 PASS, 1 FAIL, 0 REVIEW, 0 UNKNOWN

| Check | Setting | Result | Basis | Severity | Observed |
|---|---|---|---|---|---|
| LIN-01 | `PermitRootLogin` | **FAIL** | definite | high | yes |
| LIN-02 | `PasswordAuthentication` | **PASS** | policy | - | no |
| LIN-03 | `PermitEmptyPasswords` | **PASS** | definite | - | no |
| LIN-04 | `X11Forwarding` | **PASS** | policy | - | no |
| LIN-05 | `MaxAuthTries` | **PASS** | policy | - | 4 |
| LIN-06 | `ClientAliveInterval` | **PASS** | policy | - | 300 |
| LIN-07 | `AllowUsers` | **PASS** | policy | - | trainee-admin |

## Details

### LIN-01 PermitRootLogin: FAIL

- **Evidence:** `sshd -T, line 15: permitrootlogin yes`
- **Expected:** no
- **Risk:** Root is a known account name with full control of the host. Blocking direct root login forces attackers to guess a username as well, and leaves a record of which named user became root.
- **Suggested fix:** Set 'PermitRootLogin no'. First confirm that a non-root account can log in and use sudo.
- **Source:** Control 5.1.20: Ensure sshd PermitRootLogin is disabled ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** PermitRootLogin: accepted values; default is prohibit-password ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-02 PasswordAuthentication: PASS

- **Evidence:** `sshd -T, line 30: passwordauthentication no`
- **Expected:** no, or a controlled exception approved by policy
- **Source:** PasswordAuthentication: default is yes ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))
- **Source:** No control for this setting in the mapped benchmark; recommendation comes from the starter baseline ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))

### LIN-03 PermitEmptyPasswords: PASS

- **Evidence:** `sshd -T, line 40: permitemptypasswords no`
- **Expected:** no
- **Source:** Control 5.1.19: Ensure sshd PermitEmptyPasswords is disabled ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** PermitEmptyPasswords: default is no ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-04 X11Forwarding: PASS

- **Evidence:** `sshd -T, line 34: x11forwarding no`
- **Expected:** no, unless policy records that it is required
- **Source:** X11Forwarding: default is no; describes the additional exposure; Debian-based packages ship it set to yes ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))
- **Source:** Related, not identical: control 5.1.8 covers DisableForwarding (Level 2 server, Level 1 workstation) ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))

### LIN-05 MaxAuthTries: PASS

- **Evidence:** `sshd -T, line 8: maxauthtries 4`
- **Expected:** 4 or lower, or a value approved by policy
- **Source:** Control 5.1.16: Ensure sshd MaxAuthTries is configured (mapped value 4) ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** MaxAuthTries: default is 6 ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-06 ClientAliveInterval: PASS

- **Evidence:** `sshd -T, line 10: clientaliveinterval 300`
- **Expected:** the idle timeout approved by policy, in seconds
- **Source:** Control 5.1.7: Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured (mapping notes CIS requires values above 0) ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** ClientAliveInterval: default is 0, meaning messages are not sent ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

### LIN-07 AllowUsers: PASS

- **Evidence:** `sshd -T, line 81: allowusers trainee-admin`
- **Expected:** an explicit list of accounts approved by policy
- **Source:** Control 5.1.4: Ensure sshd access is configured ([CIS Benchmark for Ubuntu 24.04 LTS v1.0.0, as mapped by ComplianceAsCode (CIS PDF not read directly)](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml))
- **Source:** AllowUsers: by default, login is allowed for all users ([sshd_config(5), Ubuntu 24.04 manual page](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html))

