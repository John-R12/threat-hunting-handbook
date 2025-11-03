# 🕵️‍♂️ Attacker Behaviors for Threat Hunting

This document catalogs **common attacker behaviors** (high-level actions) and the **observable signals** you can hunt for. Use it to generate hypotheses and detection rules.

---

## 🔑 Behavior categories & signals

Each row: Behavior → What it means → Practical signals to hunt.

| Behavior | Description | Observable signals / hunting hints |
|---------|-------------|------------------------------------|
| **Reconnaissance** | Adversary gathers info about targets | Unusual DNS queries for internal hosts; port scans; suspicious OSINT mentions; abnormal login enumeration attempts |
| **Initial Access** | Entry into environment | Phishing email with suspicious attachment/link; new account creation; successful exploit logs; cloud console auth from odd geolocation |
| **Execution** | Running code on a host | Process creation for `powershell`, `cmd`, `bash`, `wmic`, `rundll32`; scripts launched from temp paths |
| **Persistence** | Techniques to maintain access | New service install, scheduled tasks/cronjobs, startup folder changes, registry autoruns |
| **Privilege Escalation** | Obtain higher privileges | Use of token manipulation APIs, `sudo` from non-admin, LSA/lsass access attempts |
| **Credential Access** | Harvesting credentials | LSASS dumps, Mimikatz strings, password spraying, suspicious Kerberos activity (TGS requests) |
| **Discovery** | Enumerating environment | AD enumeration queries, network scanning, `net view`, mapping of shares, list of running processes across many hosts |
| **Lateral Movement** | Moving to other assets | Unusual RDP/SMB/PSExec sessions, remote PowerShell Remoting, SSH from unfamiliar hosts |
| **Command & Control (C2)** | Remote control channels | Periodic beacons, DNS tunneling indicators, uncommon user agents, long-lived outbound connections to rare domains |
| **Collection** | Gathering data to exfiltrate | Access to sensitive file shares, abnormally high read rates, zip/packaging tools usage |
| **Exfiltration** | Removing data | Large uploads to cloud storage, long-duration encrypted tunnels, exfil over DNS or covert channels |
| **Impact** | Destroy/interrupt/hold systems | Mass file encryption, destructive commands, wiping artifacts, DDoS behavior |

---

## ⚙️ Hunting signals — examples & quick wins

- **Encoded scripts:** hunts for base64 / encoded command-line usage.  
- **Unusual parent process chains:** signed OS binary spawning network tool or script.  
- **Rare command usage:** look for `rundll32` executing a command with remote URL.  
- **Anomalous authentication patterns:** many failed MFA attempts followed by success from same IP.  
- **High volume DNS NXDOMAIN responses** from a host (possible exfil/tracking).  
- **Suspicious certificate usage** — self-signed certs used for outbound TLS to unknown hosts.

---

## 🧭 Building hunting hypotheses from behaviors

Template: *If [behavior] then check [observables] because [risk]*

Examples:
- If *persistence* (new scheduled task) then check *process parent, creation user, file hash* because *attacker may maintain long-term foothold*.
- If *credential access* (LSASS read) then check *recent RDP sessions and lateral movement* because *compromised credentials enable lateral spread*.

---

## 🔁 Prioritization guidance

1. Focus on behaviors impacting **high-value assets**.  
2. Prioritize **techniques with known exploitation in your sector**.  
3. Balance effort: high-impact / high-probability → hunt first.  
4. Use detection coverage matrix (ATT&CK) to see gaps.

---

## 🧰 Example detection patterns (short)

- Parent-child anomaly: `ParentImage == "explorer.exe"` AND `Image == "powershell.exe"` AND `ProcessCommandLine` contains "Invoke-*"  
- Beacon detection: periodic outbound HTTP to domain not seen before, consistent interval ± jitter.  
- Lateral movement: host A opens SMB to many internal hosts within short timeframe.

---

## 📚 References

- MITRE ATT&CK — use tactics & techniques as canonical mapping.  
- SANS / CrowdStrike resources for concrete adversary behavior examples.
