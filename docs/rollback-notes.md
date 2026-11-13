# Rollback Notes

The checker changes nothing, so running it never needs a rollback. These notes cover the manual SSH changes made during lab testing.

**Use these only in a disposable lab VM.** Never make these changes on a shared or production server as part of this project.

## Before any change

1. Take a VM snapshot, which is the full recovery path.
2. Keep a way in that doesn't use SSH. In VirtualBox, that is the console window.
3. Copy the original file: `sudo cp /etc/ssh/sshd_config ~/evidence/sshd_config.original`
4. Make changes in a new file in `/etc/ssh/sshd_config.d/`, so removing that one file undoes them.

## Applying a change safely

```bash
sudo sshd -t && sudo systemctl restart ssh
```

`sshd -t` checks the configuration first. Because of `&&`, the restart only runs if the check succeeds. Then open a **new** login before closing your current one, because existing sessions usually survive a restart even when new logins are broken.

## Undoing a change

| Situation | What to do |
|---|---|
| A lab drop-in file caused the problem | `sudo rm /etc/ssh/sshd_config.d/<file>.conf`, then run the command above |
| The main file was edited | `sudo cp ~/evidence/sshd_config.original /etc/ssh/sshd_config`, then run the command above |
| SSH login is locked out | Use the VirtualBox console and do one of the above |
| The system state is unclear | Restore the `clean-install` snapshot |

## Fix-specific cautions

| Check | How the fix can lock you out, and how to avoid it |
|---|---|
| LIN-01 `PermitRootLogin no` | Removes root login. First confirm a non-root account can log in and use `sudo`. |
| LIN-02 `PasswordAuthentication no` | Blocks anyone without a working key. Test key login in a second session first. |
| LIN-07 `AllowUsers` | Blocks every account not listed. Check that your own account is on the list. |
| LIN-05 `MaxAuthTries 4` | Clients offering many keys can run out of attempts. Use `IdentitiesOnly` with a specific key if this happens. |
| LIN-06 `ClientAliveInterval` | Idle or unresponsive sessions can disconnect. Use a value that suits long-running work. |
