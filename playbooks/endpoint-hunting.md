# 🖥️ Endpoint Threat Hunting Playbook

This playbook provides a **step-by-step guide** for hunting threats on endpoints (Windows, Linux, Mac).  
It is designed for SOC analysts, IR teams, and threat hunters to **detect, investigate, and respond** proactively to malicious activity.

---

## 🎯 Objectives

- Identify **compromised endpoints** or suspicious activity.  
- Detect **malware, lateral movement, persistence, and privilege escalation**.  
- Provide structured documentation for hunting operations.  
- Feed findings into **CTI, SIEM, or detection rules**.

---

## 🧩 Prerequisites

- Access to endpoint **logs, EDR, and system telemetry**.  
- Familiarity with **MITRE ATT&CK** techniques.  
- Tools installed for **file analysis, process inspection, and network monitoring**.  
- Baseline knowledge of normal system behavior.

---

## 🗂️ Hunting Steps

| Step | Action | Notes / Tools |
|------|--------|----------------|
| **1. Data Collection** | Gather logs, process lists, autoruns, network connections. | Sysmon, EDR agent, auditd, pslist, netstat |
| **2. IOC Matching** | Compare endpoints against known **IoCs**. | Threat intelligence feeds, MISP, OpenCTI |
| **3. Process & Binary Analysis** | Inspect suspicious processes, hashes, or binaries. | VirusTotal, Yara, PEStudio, Linux `file` & `strings` |
| **4. Persistence Check** | Identify registry run keys, cron jobs, startup scripts. | Regedit, autoruns, systemd units |
| **5. Lateral Movement Detection** | Look for unusual RDP/SMB/SSH connections. | Event logs, network logs, EDR alerts |
| **6. Privilege Escalation** | Check for admin rights abuse, token stealing, scheduled tasks. | PowerShell logs, sudo logs, EDR reports |
| **7. Anomaly Detection** | Identify deviations from baseline behavior. | Behavioral analytics, SIEM, UEBA tools |
| **8. Documentation & Reporting** | Record findings, evidence, and mitigation actions. | Hunting template, CTI integration |

---

## ⚙️ Best Practices

- Always **maintain chain of custody** for evidence.  
- Correlate **endpoint findings with network and CTI data**.  
- Repeat hunts regularly and update your **IOC library**.  
- Use **TLP or internal classification** for sensitive findings.  
- Feed outcomes into **detection rules and alerts**.

---

## 📚 References

- MITRE ATT&CK – *Enterprise, ICS, Mobile*  
- SANS – *Practical Threat Hunting*  
- Microsoft – *Windows Threat Hunting Guidance*  
- CrowdStrike – *Hunting on Endpoints: Techniques and Tools*
