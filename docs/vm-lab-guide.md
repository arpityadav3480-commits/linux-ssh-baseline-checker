# VM Lab Guide

These steps collect the real evidence for the V1 to V6 tests in [test-matrix.md](test-matrix.md). Run them only in a disposable VM.

> **Status:** run on 13 November 2026. All six results matched; see [test-matrix.md](test-matrix.md) and [evidence/vm/](../evidence/vm/). The notes below record where the run differed from the first draft of these steps.

## 1. Create the VM

Run these in PowerShell. They download Ubuntu Server 24.04.5, then create a VM with 2 GB RAM, 2 CPUs and a 20 GB disk. The NAT network and the port forward bound to `127.0.0.1` mean only your own PC can reach the VM.

```powershell
New-Item -ItemType Directory -Force D:\VMs | Out-Null
curl.exe -L -C - -o D:\VMs\ubuntu-24.04.5-live-server-amd64.iso https://releases.ubuntu.com/24.04/ubuntu-24.04.5-live-server-amd64.iso
Get-FileHash D:\VMs\ubuntu-24.04.5-live-server-amd64.iso -Algorithm SHA256
```

The hash must be `97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8`.

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb createvm --name redkross-lab --ostype Ubuntu_64 --basefolder D:\VMs --register
& $vb modifyvm redkross-lab --memory 2048 --cpus 2 --vram 16 --graphicscontroller vmsvga --nic1 nat --natpf1 "ssh,tcp,127.0.0.1,2222,,22" --boot1 disk --boot2 dvd --boot3 none --boot4 none
& $vb createmedium disk --filename D:\VMs\redkross-lab\redkross-lab.vdi --size 20480
& $vb storagectl redkross-lab --name SATA --add sata --controller IntelAhci --portcount 2
& $vb storageattach redkross-lab --storagectl SATA --port 0 --device 0 --type hdd --medium D:\VMs\redkross-lab\redkross-lab.vdi
& $vb storageattach redkross-lab --storagectl SATA --port 1 --device 0 --type dvddrive --medium D:\VMs\ubuntu-24.04.5-live-server-amd64.iso
& $vb startvm redkross-lab
```

During installation, set the username to **`trainee-admin`** (the lab policy approves this account) and choose **Install OpenSSH server**. Leave "Allow password authentication over SSH" ticked so the next step can copy files in.

**If the install fails at "installing kernel"**, read the error with Help → Enter shell: `grep -E 'Err:|E: ' /var/log/installer/curtin-install.log`. In this run, one server behind `in.archive.ubuntu.com` refused connections. Choosing "Restart the installer" and changing the mirror to `http://archive.ubuntu.com/ubuntu/` fixed it.

## 2. Copy the tool and take a snapshot

Run this from the project folder on your PC:

```bash
scp -P 2222 -r baseline_checker.py baseline trainee-admin@127.0.0.1:~/
```

**Optional: use a key.** V3 turns off password login. If you add a key now, new logins and the copy in step 4 keep working, so you don't need to undo the hardening first. This run used a key made only for this lab:

```bash
ssh-keygen -t ed25519 -N "" -C redkross-lab -f redkross_lab_key
ssh-copy-id -i redkross_lab_key.pub -p 2222 trainee-admin@127.0.0.1
```

If `ssh-copy-id` is not available, append the `.pub` line to `~/.ssh/authorized_keys` in the VM (folder mode 700, file mode 600). Keep the private key out of the repository.

Power off the VM with `sudo poweroff`, then take a snapshot named **`clean-install`** and start the VM again:

```powershell
& $vb snapshot redkross-lab take clean-install
& $vb startvm redkross-lab
```

Log in with `ssh -p 2222 trainee-admin@127.0.0.1` and run the remaining steps there, because the console window can't accept pasted text. **Stay logged in throughout.** V3 turns off password login, but your open session keeps working. The console window is your backup if SSH breaks.

## 3. Run the tests

Save each report as you go:

```bash
mkdir -p ~/evidence
RUN="sudo python3 baseline_checker.py --live --policy baseline/lab_policy.json --format markdown"
```

**V1: Fresh install.** Expect `LIN-01` to fail, because the default is `prohibit-password`. `sshd -T` prints it as `without-password`. With the lab policy, LIN-02 and LIN-04 to LIN-07 fail too; LIN-02 fails because the installer's `50-cloud-init.conf` sets `PasswordAuthentication yes`.

```bash
$RUN > ~/evidence/v1-fresh-install.md; echo "exit=$?"
```

**V2: Read-only proof.** Expect the two hash lists to be identical. The evidence file keeps both lists, not just the verdict.

```bash
sudo find /etc/ssh -type f -exec sha256sum {} + | sort > /tmp/before.txt
$RUN > /dev/null
sudo find /etc/ssh -type f -exec sha256sum {} + | sort > /tmp/after.txt
{ echo "Files hashed: $(wc -l < /tmp/before.txt)"; echo "== before =="; cat /tmp/before.txt; echo "== after =="; cat /tmp/after.txt; echo "== diff =="; diff /tmp/before.txt /tmp/after.txt && echo "UNCHANGED"; } > ~/evidence/v2-read-only.txt
```

**V3: Fix by hand, then retest.** Expect all 7 to pass and exit 0.

```bash
sudo cp /etc/ssh/sshd_config ~/evidence/sshd_config.original
sudo tee /etc/ssh/sshd_config.d/10-lab-hardened.conf > /dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers trainee-admin
EOF
sudo sshd -t && sudo systemctl restart ssh
$RUN > ~/evidence/v3-after-fix.md; echo "exit=$?"
```

**V4: Change a setting on purpose.** Files load in name order and the first value wins, so `00-` overrides `10-`. Expect only `LIN-01` to fail, and exit 1.

```bash
echo "PermitRootLogin yes" | sudo tee /etc/ssh/sshd_config.d/00-lab-weak.conf
sudo sshd -t && sudo systemctl restart ssh
$RUN > ~/evidence/v4-detect-change.md; echo "exit=$?"
```

**V5: Roll back that change.** Expect all 7 to pass and exit 0.

```bash
sudo rm /etc/ssh/sshd_config.d/00-lab-weak.conf
sudo sshd -t && sudo systemctl restart ssh
$RUN > ~/evidence/v5-after-rollback.md; echo "exit=$?"
```

**V6: Run without sudo.** Expect a clear error and exit 3. On this VM, `sshd -T` stops at `50-cloud-init.conf`, which only root can read. Use a new login, so no cached sudo credentials are involved.

```bash
python3 baseline_checker.py --live > ~/evidence/v6-no-sudo.txt 2>&1; echo "exit=$?" | tee -a ~/evidence/v6-no-sudo.txt
```

## 4. Copy the evidence back

If you added a key in step 2, skip straight to the copy. Otherwise the hardened config has turned off password login, so copying over SSH will fail. Remove the hardening first:

```bash
sudo rm /etc/ssh/sshd_config.d/10-lab-hardened.conf
sudo sshd -t && sudo systemctl restart ssh
```

Then run this from the project folder on your PC:

```bash
scp -P 2222 -r 'trainee-admin@127.0.0.1:~/evidence/*' evidence/vm/
```

Quote the remote path as shown, so your own shell doesn't try to expand the `*`. To show which build was tested, this run also saved the VM's versions and the tool's hashes to `v0-environment.txt` before copying.

Create `evidence/vm/` first. Before committing, read the files and make sure they show nothing private. Then restore the `clean-install` snapshot, or delete the VM.
