# 🎯 Threat Hunting Scenarios

Scenario-based exercises provide **practical hunting experience**.  
They can be used for **SOC training, tabletop exercises, or operational hunts**.

---

## 📁 Example Scenarios

| Scenario | Description | Objective | Tools / Notes |
|----------|-------------|-----------|---------------|
| Ransomware Infection | Investigate endpoints for early signs of ransomware | Detect and isolate before encryption | EDR, SIEM, IOC feeds |
| Suspicious Cloud Access | Identify unusual cloud account behavior | Detect compromised accounts | Cloud logs, CSPM, SIEM |
| Lateral Movement via SMB | Hunt for unauthorized lateral movements | Detect lateral propagation | Network logs, EDR, ATT&CK T1021 |
| Data Exfiltration | Detect unusual outbound transfers | Prevent sensitive data loss | Proxy logs, DLP, UEBA |

---

## ⚙️ How to Use

1. Select scenario based on **environment and threat context**.  
2. Follow **playbook and hunting steps** adapted to the scenario.  
3. Document findings in the **hunting template**.  
4. Feed results into **detection rules, alerts, and CTI**.

---

## 📚 References

- MITRE ATT&CK – *Enterprise, ICS, Mobile*  
- SANS – *Threat Hunting Examples & Exercises*  
- CrowdStrike – *Threat Hunting Case Studies*
