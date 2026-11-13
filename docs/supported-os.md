# Supported Operating Systems

| Mode | Runs on | Status |
|---|---|---|
| File review (`--config`) | Any OS with Python 3.10+ | Tested on Windows 11 with Python 3.13 |
| Live (`--live`) | Ubuntu 24.04 LTS with `openssh-server` | Tested on Ubuntu 24.04.5 LTS (OpenSSH 9.6p1, Python 3.12.3) in a VirtualBox VM on 13 November 2026; see V1 to V6 in [test-matrix.md](test-matrix.md) |

Any other OS or version is refused in live mode with exit code 3, because the citations and defaults were checked against Ubuntu 24.04 only. You can still save that machine's `sshd -T` output and review it with `--config`, but the citations may not apply to it.

## Requirements for live mode

- Python 3 (included in Ubuntu Server)
- `sshd` from `openssh-server`
- `sudo`, because `sshd -T` needs root. On the test VM it could not read the installer's `50-cloud-init.conf` (mode 0600) without root. The tool never elevates itself.

## Version differences to watch

- **Package defaults differ from upstream.** Ubuntu's shipped config sets `X11Forwarding yes`, while the manual's default is `no`. File mode reports the documented default for unset values, so use live mode for the real answer.
- **Drop-in files override the main file.** Ubuntu includes `/etc/ssh/sshd_config.d/*.conf` at the top of `sshd_config`. The Ubuntu Server installer adds `50-cloud-init.conf` there, with `PasswordAuthentication yes` if password login was allowed during installation.
