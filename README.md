# 🔍 SOC Investigation: Linux Logging for SOC – Auth Logs, System Logs, Bash History & Auditd

[![Platform](https://img.shields.io/badge/Platform-TryHackMe-black?style=flat&logo=tryhackme)](https://tryhackme.com)
[![Path](https://img.shields.io/badge/Path-SOC%20Level%201-blue?style=flat)](https://tryhackme.com/path/outline/soclevel1)
[![Topic](https://img.shields.io/badge/Topic-Linux%20Log%20Analysis%20%26%20Runtime%20Monitoring-007ACC?style=flat)]()
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat)]()
[![Status](https://img.shields.io/badge/Status-Completed-success?style=flat)]()
[![Tools](https://img.shields.io/badge/Tools-auditd%20%7C%20ausearch%20%7C%20grep%20%7C%20auth.log%20%7C%20syslog-blue?style=flat)]()

Hands-on Linux log analysis investigation covering the four key log sources every SOC analyst needs to master on Linux systems — authentication logs, system/package logs, bash history forensics, and auditd runtime monitoring. Investigated a compromised Linux host to uncover SSH brute-force activity, backdoor account creation, suspicious tool downloads, and network scanning.

**Attack chain uncovered:**
> SSH Brute-Force → Backdoor Account Creation (xerxes + sudo) → Tool Download (naabu via wget) → Network Scan (192.168.50.0/24)

---

## 📌 Investigation Summary

| Field | Detail |
|-------|--------|
| **Target Host** | thm-vm (Ubuntu Linux — AWS) |
| **Log Sources** | `/var/log/syslog`, `/var/log/auth.log`, `/var/log/dpkg.log`, `~/.bash_history`, `/var/log/audit/audit.log` |
| **Attacker IP** | `10.14.94.82` — SSH brute-force across multiple usernames |
| **Backdoor Account** | `xerxes` — added to `sudo` group |
| **Tool Downloaded** | `naabu_2.3.5_linux_amd64.zip` from GitHub via `wget` |
| **Network Scanned** | `192.168.50.0/24` using naabu |
| **Secret File Accessed** | `/secret.thm` — first opened 08/13/25 18:36:54 |
| **Flag Found** | `THM{note_to_remember}` in root bash history |
| **Outcome** | Full attack chain reconstructed across 4 Linux log sources |

---

## 🎯 Key Findings

| # | Finding | Log Source |
|---|---------|-----------|
| 1 | NTP time server contacted: `ntp.ubuntu.com` | `/var/log/syslog` |
| 2 | Kernel Yama message: `becoming mindful.` | `/var/log/syslog` |
| 3 | SSH brute-force from `10.14.94.82` — multiple usernames targeted | `/var/log/auth.log` |
| 4 | Backdoor account `xerxes` created and added to `sudo` group | `/var/log/auth.log` |
| 5 | `unzip` version `6.0-28ubuntu4.1` installed | `/var/log/dpkg.log` |
| 6 | Flag `THM{note_to_remember}` found in root `.bash_history` | `~/.bash_history` |
| 7 | `/secret.thm` first accessed: `08/13/25 18:36:54` | `auditd` (key: file_thmsecret) |
| 8 | `naabu_2.3.5_linux_amd64.zip` downloaded from GitHub via `wget` | `auditd` (key: proc_wget) |
| 9 | Network range `192.168.50.0/24` scanned using naabu | `auditd` (audit.log) |

---

## 🔎 Investigation Walkthrough

### Phase 1 — System Log Analysis: `/var/log/syslog`

**Commands used**:
```bash
cat /var/log/syslog | grep "ntp"
grep -i "yama" /var/log/syslog
```

The syslog file revealed the VM contacted `ntp.ubuntu.com` for time synchronisation. Multiple NTP sync attempts timed out across different IP addresses (`185.125.190.57`, `185.125.190.58`, `91.189.91.157`) before eventually succeeding — a useful baseline for correlating attack timestamps.

Filtering for `yama` revealed the Linux Security Module (LSM) kernel message: `Yama: becoming mindful.` — confirming Yama was initialised as part of the LSM security stack on boot. Yama restricts process tracing (ptrace), making it a defensive control relevant to SOC monitoring.

**Key insight**: `/var/log/syslog` is the starting point for any Linux investigation — it aggregates system events, service starts, kernel messages, and NTP activity that help establish a reliable timeline.

#### 📸 Screenshot 1 — `/var/log/syslog`: NTP Server `ntp.ubuntu.com` Identified
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/6d192201-61ac-46e2-bed3-5d3ff83863a8" />

*syslog — systemd-timesyncd contacting ntp.ubuntu.com — multiple timeout attempts visible before sync*

#### 📸 Screenshot 2 — `/var/log/syslog`: Kernel Yama Message Confirmed
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/daa09d31-780e-4f8b-b8aa-9a67db49bc11" />

*grep -i "yama" /var/log/syslog — kernel: Yama: becoming mindful — LSM initialisation confirmed*

---

### Phase 2 — Authentication Log Analysis: `/var/log/auth.log`

**Commands used**:
```bash
cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'
cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['
```

Authentication log analysis revealed a clear attack pattern from `10.14.94.82` — failed SSH login attempts across multiple usernames (`root`, `admin`, `support`) in rapid succession, a textbook credential stuffing / password spraying attack. The attacker targeted several common account names before giving up.

User management log analysis exposed the persistence mechanism — `useradd` created account `xerxes` with UID=1001, followed immediately by `usermod` adding `xerxes` to both the `sudo` and shadow `sudo` groups — granting full administrative access.

**Key indicator**: `useradd` followed within seconds by `usermod` adding to `sudo` — this sequence is the definitive Linux backdoor account creation signature.

#### 📸 Screenshot 3 — `/var/log/auth.log`: SSH Brute-Force from `10.14.94.82`
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/50758143-fc4f-4f3d-8b22-9d96a5a19928" />

*auth.log — Failed password for root, admin, support from 10.14.94.82 — credential stuffing attack confirmed*

#### 📸 Screenshot 4 — `/var/log/auth.log`: Backdoor Account `xerxes` Created + Added to sudo
<img width="1366" height="733" alt="image" src="https://github.com/user-attachments/assets/58cd0f99-fe53-44b7-a965-0886aab51f7b" />

*auth.log — useradd: new user xerxes, usermod: add xerxes to group sudo — backdoor account with elevated privileges confirmed*

---

### Phase 3 — Package Manager & Bash History Analysis

**Commands used**:
```bash
grep unzip /var/log/dpkg.log
cat /root/.bash_history
```

Package manager log analysis confirmed `unzip 6.0-28ubuntu4.1` was installed on 2025-08-12 — a prerequisite tool for the naabu download and extraction that followed. Package installation timestamps are valuable for establishing attacker tool staging timelines.

Bash history analysis of the root account revealed the full command history including the flag `THM{note_to_remember}` embedded via `echo "THM{note_to_remember}" >> notes.txt` — confirming the attacker operated under root context and left evidence in bash history despite its limitations.

**Key insight**: Bash history is often overlooked but can contain decisive evidence — always check `.bash_history` for every active user, not just the primary account.

#### 📸 Screenshot 5 — `/var/log/dpkg.log`: `unzip 6.0-28ubuntu4.1` Installation Confirmed
<img width="1366" height="726" alt="image" src="https://github.com/user-attachments/assets/eb97e99b-f43d-4b5f-8989-10dfb6563e97" />

*dpkg.log — install unzip:amd64 6.0-28ubuntu4.1 — package installation timestamp confirms tool staging*

#### 📸 Screenshot 6 — `~/.bash_history`: Flag `THM{note_to_remember}` Recovered
<img width="1366" height="729" alt="image" src="https://github.com/user-attachments/assets/5bca7550-b667-4b1b-a4ce-9ae587a7cdad" />

*root .bash_history — echo "THM{note_to_remember}" >> notes.txt — flag confirmed, attacker operated as root*

---

### Phase 4 — Auditd Runtime Monitoring: File Access, Tool Download & Network Scan

**Commands used**:
```bash
ausearch -i -k file_thmsecret
ausearch -i -k proc_wget | grep "naabu"
ausearch -i | grep "naabu"
```

#### 4a — Secret File Access

Auditd key `file_thmsecret` captured the first access to `/secret.thm` at `08/13/25 18:36:54` — the `cat` command was used via `/usr/bin/cat` under the `ubuntu` auid with root uid, confirming privilege escalation to root before file access. The audit log captured the exact syscall (`openat`), session (ses=30), and tty (pts1) — providing full forensic context invisible to standard logs.

#### 4b — Tool Download via wget

Auditd key `proc_wget` captured the full wget command: `wget https://github.com/projectdiscovery/naabu/releases/download/v2.3.5/naabu_2.3.5_linux_amd64.zip -O /tmp/naabu.zip` — confirming the attacker downloaded the naabu network scanner from GitHub. The PROCTITLE field exposed the exact filename: `naabu_2.3.5_linux_amd64.zip`.

#### 4c — Network Scanning

Correlating the naabu process (auid=ubuntu, uid=root), the auditd logs captured the full execution chain: `wget` → `unzip naabu.zip` → `chmod +x naabu` → `./naabu -host 192.168.50.0/24 -top-ports`. The network scan targeted `192.168.50.0/24` using naabu's top ports scan — internal network reconnaissance confirming the attacker was mapping the local network post-compromise.

**Key insight**: Auditd is the only log source that captured the tool download, extraction, permission change, and network scan as a connected chain — none of this would be visible in auth.log or syslog alone.

#### 📸 Screenshot 7 — Auditd: `/secret.thm` First Accessed at `08/13/25 18:36:54`
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/f9524d4d-24d0-4c3b-b082-f2e9878bda7a" />

*ausearch -i -k file_thmsecret — proctitle=cat /secret.thm, syscall=openat, timestamp: 08/13/25 18:36:54*

#### 📸 Screenshot 8 — Auditd: `naabu_2.3.5_linux_amd64.zip` Downloaded via wget
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/ebd372cc-b45d-49b1-9177-9fcb60520973" />

*ausearch -i -k proc_wget — proctitle=wget https://github.com/.../naabu_2.3.5_linux_amd64.zip — tool download confirmed*

#### 📸 Screenshot 9 — Auditd: Network Scan of `192.168.50.0/24` Using naabu
<img width="1366" height="728" alt="image" src="https://github.com/user-attachments/assets/aef5138f-9e08-4633-8071-4207293807a6" />

*auditd — proctitle=./naabu -host 192.168.50.0/24 -top-ports — internal network reconnaissance confirmed*

---

## 🧭 MITRE ATT&CK Mapping

| Tactic | Technique | ID | Observed |
|--------|-----------|----|----------|
| Initial Access | Brute Force: Password Spraying | T1110.003 | SSH brute-force from `10.14.94.82` across multiple usernames |
| Persistence | Create Account: Local Account | T1136.001 | `xerxes` created — `useradd` + `usermod sudo` |
| Privilege Escalation | Abuse Elevation Control: Sudo | T1548.003 | `xerxes` added to sudo group |
| Discovery | Network Service Discovery | T1046 | naabu scanning `192.168.50.0/24` |
| Command & Control | Ingress Tool Transfer | T1105 | naabu downloaded via wget from GitHub |
| Collection | Data from Local System | T1005 | `/secret.thm` accessed via `cat` |
| Defense Evasion | Indicator Removal: Clear Linux Logs | T1070.002 | `rm *` observed in logrotate directory in bash history |

---

## 🛡 Containment & Hardening Recommendations

### Immediate Response
- **Disable and delete `xerxes` account** — `userdel -r xerxes`
- **Block `10.14.94.82`** at firewall — confirmed SSH brute-force source
- **Investigate `/secret.thm`** — confirm what data was accessed
- **Remove naabu** from `/tmp/naabu` — attacker reconnaissance tool
- **Rotate all SSH keys and passwords** — compromise scope unknown

### Authentication Hardening
```bash
# Disable password-based SSH authentication
sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

# Implement fail2ban to block brute-force
apt install fail2ban
# Configure /etc/fail2ban/jail.local: maxretry=5, bantime=3600
```

### Detection Rules (SIEM)
```bash
# SSH brute-force detection
Alert: >5 "Failed password" from single IP in /var/log/auth.log within 60 seconds

# Backdoor account creation
Alert: useradd + usermod sudo within same session (same tty/timestamp)

# Privileged tool download
Alert: auditd proc_wget — URL contains github.com + binary/zip extension

# Network scanning from internal host
Alert: auditd — naabu OR nmap OR masscan execution with -host or network range argument

# Sensitive file access
Alert: auditd file_thmsecret key — any openat syscall on monitored files
```

### Auditd Rules to Add
Monitor sudo group modifications
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

Monitor new user creation
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/useradd -k user_creation
-a always,exit -F arch=b64 -S execve -F exe=/usr/sbin/usermod -k user_modification

Monitor /tmp execution
-a always,exit -F arch=b64 -S execve -F dir=/tmp -k tmp_execution

---

## 📌 Investigator Notes

> Linux investigations require fluency across multiple log sources — no single file tells the complete story.
>
> In this investigation:
> `/var/log/syslog` → established the system timeline and confirmed boot security state
> `/var/log/auth.log` → revealed the brute-force and backdoor account creation
> `/var/log/dpkg.log` → confirmed attacker tool staging (unzip installation)
> `~/.bash_history` → exposed attacker commands including the flag
> `auditd` → the only source that captured file access, tool download, and network scan as a connected chain
>
> The most important lesson: **auditd provides visibility that no default Linux log can match.**
> Without it, the naabu download and network scan would have been completely invisible.
> Runtime monitoring is not optional — it is the difference between detecting and missing the attack.

---

## 📌 Key Linux Log Sources Reference

| Log File | Purpose | Key Commands |
|----------|---------|-------------|
| `/var/log/syslog` | System events, kernel messages, NTP | `grep`, `cat` |
| `/var/log/auth.log` | SSH, sudo, user management | `grep sshd`, `grep useradd` |
| `/var/log/dpkg.log` | Package installation history | `grep <package>` |
| `~/.bash_history` | User command history | `cat`, `history` |
| `/var/log/audit/audit.log` | Runtime events (auditd) | `ausearch -i -k <key>` |

---

## 📌 Skills Demonstrated

- Linux authentication log analysis — SSH brute-force and backdoor account detection
- System and package log investigation — `syslog`, `dpkg.log`, `kern.log`
- Bash history forensics — command recovery and flag extraction
- Auditd runtime monitoring — file access, process creation, and network event correlation
- `ausearch` query writing for targeted event investigation
- Full Linux attack chain reconstruction across 4 log sources
- MITRE ATT&CK mapping for Linux-based attacks
- Structured, SOC-grade incident documentation

---

**Completed**: May 2026

Full portfolio of SOC investigations available at [github.com/ugbomakyrian5-web](https://github.com/ugbomakyrian5-web)

Feel free to fork, star, or reach out. Open to feedback and collaboration!

MIT License – see the [LICENSE](LICENSE) file for details.
