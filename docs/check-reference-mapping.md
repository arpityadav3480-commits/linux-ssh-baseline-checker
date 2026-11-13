# Check-to-Reference Mapping

Every check in [baseline/ssh_baseline.json](../baseline/ssh_baseline.json) traces back to the starter baseline and at least one published source. The tool refuses to run a check that has no citation.

**Sources accessed:** 30 October 2026.

| Check | Setting | Starter recommendation | CIS Ubuntu 24.04 v1.0.0 (mapped) | sshd_config(5) | Why this basis |
|---|---|---|---|---|---|
| LIN-01 | `PermitRootLogin` | `no` | 5.1.20: Ensure sshd PermitRootLogin is disabled | Default is `prohibit-password` | **Definite:** fixed recommendation |
| LIN-02 | `PasswordAuthentication` | `no_or_controlled` | No control found | Default is `yes` | **Policy:** a controlled exception is allowed |
| LIN-03 | `PermitEmptyPasswords` | `no` | 5.1.19: Ensure sshd PermitEmptyPasswords is disabled | Default is `no` | **Definite:** fixed recommendation |
| LIN-04 | `X11Forwarding` | `no_if_not_required` | Related only: 5.1.8 covers `DisableForwarding` | Default is `no`; describes the added exposure | **Policy:** depends on whether it is needed |
| LIN-05 | `MaxAuthTries` | `4_or_approved_value` | 5.1.16: Ensure sshd MaxAuthTries is configured (mapped value 4) | Default is 6 | **Policy:** another value can be approved |
| LIN-06 | `ClientAliveInterval` | `set_approved_idle_timeout` | 5.1.7: Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured | Default is 0, meaning messages are not sent | **Policy:** the approved timeout is an organisation choice |
| LIN-07 | `AllowUsers` | `explicit_approved_accounts` | 5.1.4: Ensure sshd access is configured | By default, all users may log in | **Policy:** only the organisation knows the approved accounts |

## Differences from the starter baseline

- **LIN-03 severity:** the starter file gives `"severity": "pass"`. That is a result, not a severity, so this baseline rates the risk as `high`. This is my judgement, based on anyone reachable being able to use an account with an empty password.
- **Results are calculated:** the starter file's `observed` values describe one fictional host. The tool reads the real configuration instead. Test T06 confirms that the starter's values match the sample config.

## Limits of these sources

- **CIS:** the CIS website blocked automated access when I tried to reach it, and the benchmark PDF was not read. Control numbers and titles come from the [ComplianceAsCode mapping](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml), which lists CIS Ubuntu 24.04 LTS v1.0.0. They should be checked against the PDF before being relied on. That file is on a changing branch, so its contents may differ after the access date.
- **LIN-02:** the mapping has no control for `PasswordAuthentication`. Its recommendation comes from the starter baseline, and the rationale is my own reasoning, not a quote from a standard.
- **Ubuntu Security Guide:** read as background only. USG was not run, so it is not evidence for any result here.

## Source details

| Source | Used for |
|---|---|
| [sshd_config(5), Ubuntu 24.04](https://manpages.ubuntu.com/manpages/noble/man5/sshd_config.5.html) | Defaults, accepted values, first-value rule, `Match` and `Include` behaviour, Debian-packaged settings |
| [sshd_config(5), OpenBSD](https://man.openbsd.org/sshd_config) | Upstream comparison for the option descriptions |
| [sshd(8), Ubuntu 24.04](https://manpages.ubuntu.com/manpages/noble/man8/sshd.8.html) | `-T` extended test mode |
| [Ubuntu Server Guide: OpenSSH server](https://documentation.ubuntu.com/server/how-to/security/openssh-server/) | `sshd_config.d` override behaviour, `sshd -t` before restarting, copying the original config |
| [ComplianceAsCode cis_ubuntu2404.yml](https://github.com/ComplianceAsCode/content/blob/master/controls/cis_ubuntu2404.yml) | CIS control numbers and titles |
| Starter pack `04_LINUX_CONFIGS` | Checks, recommendations, fixtures and output requirements |
