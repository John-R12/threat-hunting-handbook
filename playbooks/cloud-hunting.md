# ☁️ Cloud Threat Hunting Playbook

This playbook provides a **step-by-step guide** for hunting threats in cloud environments (IaaS, PaaS, SaaS).  
It is designed for SOC analysts, IR teams, and cloud security engineers to **detect suspicious activity, misconfigurations, and attacks in the cloud**.

---

## 🎯 Objectives

- Identify **compromised cloud accounts** or suspicious activity.  
- Detect **unauthorized access, data exfiltration, and lateral movement**.  
- Provide structured documentation for cloud hunting operations.  
- Feed findings into **SIEM, CTI, and security automation workflows**.

---

## 🧩 Prerequisites

- Access to **cloud logs, API activity, and audit trails**.  
- Familiarity with **cloud services architecture** (AWS, Azure, GCP, SaaS).  
- Tools for **cloud monitoring and analysis** (CloudTrail, CloudWatch, Azure Sentinel).  
- Knowledge of **identity and access management (IAM) best practices**.

---

## 🗂️ Hunting Steps

| Step | Action | Notes / Tools |
|------|--------|----------------|
| **1. Log Collection** | Gather audit logs, authentication events, and API calls. | CloudTrail (AWS), Azure Monitor, GCP Logging, SIEM |
| **2. IOC Matching** | Check accounts and activities against known IoCs. | Threat feeds, MISP, OpenCTI |
| **3. User & Role Analysis** | Identify abnormal logins, privilege escalations, or IAM changes. | IAM logs, cloud console, SIEM alerts |
| **4. Network & Traffic Analysis** | Review VPC flow logs, firewall rules, and external connections. | VPC Flow Logs, NSG logs, Zeek, SIEM |
| **5. Configuration & Misuse Detection** | Detect insecure S3 buckets, exposed endpoints, or overly permissive roles. | Cloud Security Posture Management (CSPM) tools |
| **6. Data Exfiltration Detection** | Monitor large or unusual data transfers. | Cloud storage audit logs, DLP integration |
| **7. Anomaly Detection** | Look for deviations from normal cloud behavior. | UEBA, machine learning models, historical baselines |
| **8. Documentation & Reporting** | Record hunting findings, alerts, and remediation steps. | Hunting template, internal reporting tools |

---

## ⚙️ Best Practices

- Maintain **baseline metrics** for cloud activity.  
- Enforce **least privilege principles** and monitor deviations.  
- Correlate cloud findings with **endpoint and network hunts**.  
- Apply **TLP or internal classification** when sharing findings.  
- Review **historical logs** periodically for retrospective hunting.

---

## 📚 References

- MITRE ATT&CK – *Cloud TTPs (Enterprise, ICS, SaaS)*  
- AWS Security Best Practices – *Threat Hunting Guidance*  
- Azure Sentinel – *Hunting Queries & Analytics*  
- GCP Security Command Center – *Threat Detection and Monitoring*
