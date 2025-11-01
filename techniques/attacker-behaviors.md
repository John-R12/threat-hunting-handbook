# 🕵️‍♂️ Attacker Behaviors for Threat Hunting

Understanding **common adversary behaviors** helps hunters anticipate activity and detect threats early.

---

## 🧩 Key Behavior Categories

| Behavior | Description | Examples / Notes |
|----------|-------------|----------------|
| Initial Access | How attackers enter the environment | Phishing, stolen credentials, cloud misconfigurations |
| Execution | Running malicious code | PowerShell scripts, malware binaries, cron jobs |
| Persistence | Maintain access over time | Scheduled tasks, startup scripts, registry keys |
| Lateral Movement | Moving within the environment | RDP, SMB, SSH, compromised service accounts |
| Exfiltration | Stealing data | Large file transfers, cloud storage uploads, DNS tunneling |
| Defense Evasion | Avoid detection | Log clearing, obfuscation, living-off-the-land binaries |

---

## ⚙️ How to Use

1. Reference behaviors when analyzing **hunting results**.  
2. Map observed activity to **MITRE ATT&CK or internal taxonomy**.  
3. Prioritize hunts based on **likely adversary goals and high-value assets**.

---

## 📚 References

- MITRE ATT&CK – *Enterprise, ICS, Mobile*  
- SANS – *Threat Hunting Curriculum*
