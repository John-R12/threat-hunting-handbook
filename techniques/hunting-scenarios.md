# 🎯 Threat Hunting Scenarios

Scenario-driven hunts accelerate operational readiness. Each scenario below contains: objective, data sources, hypothesis, hunting steps, example queries / checks, and expected outcomes.

---

## Scenario 1 — Suspicious PowerShell / Living-off-the-Land

**Objective:** Detect malicious PowerShell usage indicative of initial compromise or post-exploitation.

**Data sources:** Process creation logs, PowerShell logs, Sysmon, EDR process telemetry, script block logs.

**Hypothesis:** Attackers use encoded PowerShell to run payloads and avoid detection.

**Hunting steps:**
1. Search for `-EncodedCommand`, `-EP bypass`, `IEX` in command lines.  
2. Identify parent process and network activity post-execution.  
3. Extract and decode encoded commands for TTP mapping and IOC extraction.  
4. Cross-check hashes/domains/IPs with CTI feeds.

**Example Splunk query (template):**
```spl
index=process OR index=powerShell EventCode=4688 CommandLine="*powershell* -EncodedCommand*" 
| table _time, host, user, CommandLine, ParentImage
```

**Expected outcome:** List of suspicious hosts and decoded commands; new IOCs for enrichment.

---

## Scenario 2 — Unusual Outbound Beaconing (C2)
**Objective:** Detect hosts acting as beacons to remote C2 infrastructure.

**Data sources:** DNS logs, proxy logs, network flows, TLS SNI logs.

**Hypothesis:** Compromised host connects periodically to a remote domain with regular interval.

**Hunting steps:**

1. Identify external endpoints with high periodicity from single hosts.
2. Correlate with unusual user agents, certificate anomalies, or non-standard ports.
3. Inspect process on host initiating connections.

**Simple detection pattern (pseudo):**
- Count outbound connections per host to external domain grouped by minute/hour → look for regular intervals.

**Expected outcome:** Detect hosts with beaconing behavior; pivot to process & file artifacts.

---

## Scenario 3 — Credential Dumping & Lateral Movement
**Objective:** Find signs of credential harvesting that may lead to lateral movement.

**Data sources:** Authentication logs, EDR alerts, Windows event logs (4624/4688), domain controller logs.

**Hypothesis:** Credential dumping tools (Mimikatz, LSASS memory read) are used, followed by lateral logins.

**Hunting steps:**
1. Detect LSASS read attempts or suspicious process injecting into LSASS.
2. Look for subsequent anomalous authentication (new source IP or odd hours).
3. Identify new scheduled tasks or service creation for persistence.

**Expected outcome:** Early detection of credential compromise to stop lateral spread.

---

## Scenario 4 — Data Staging & Exfiltration
**Objective:** Detect staging of sensitive data and exfil attempts.

**Data sources:** File access logs, DLP alerts, proxy logs, cloud storage audit logs, NetFlow.

**Hypothesis:** Attacker collects files to staging host and then exfiltrates via cloud upload or covert channel.

**Hunting steps:**
1. Identify hosts reading large volumes of files of interest (sensitive directories).
2. Look for archive creation (zip/rar) or unusual file transfer utilities.
3. Correlate with outbound connections to cloud storage providers or unknown hosts.

**Expected outcome:** Block or isolate staging host, collect forensic artifacts, and alert data owners.

---

## Scenario 5 — Suspicious Cloud Account Activity
**Objective:** Detect compromised cloud accounts or misuse of service principals.

**Data sources:** Cloud audit logs (CloudTrail/AzureActivity/GCP audit), IAM logs, API calls.

**Hypothesis:** Malicious actor uses valid cloud credentials to enumerate resources and exfiltrate or spin up infra.

**Hunting steps:**

1. Detect console logins from new geolocation or tor exit nodes.
2. Monitor for privilege escalation actions (IAM policy changes).
3. Look for mass read/list calls on storage buckets or DB exports.

**Expected outcome:** Revoke compromised creds, rotate keys, and remediate over-permissive roles.

---

## 🧭 How to use scenarios
- Use scenarios for training (tabletop / hands-on) and operational hunts.
- Record findings in the hunting template and feed back into CTI and detection rules.
- Map each scenario to ATT&CK techniques and add a corresponding query to your hunting library.

## 📚 References
- MITRE ATT&CK — map each scenario to TTPs.
- Vendor threat hunting writeups (CrowdStrike, Mandiant, etc.) for concrete examples.
