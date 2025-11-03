# 📊 TTP Mapping for Threat Hunting

Mapping observed activity to **MITRE ATT&CK TTPs** allows hunters to understand adversary behavior, prioritize hunts, and design targeted detections.

> Goal: move from raw observables (logs, IOCs) to behavior-centric detections (TTPs) that generalize across malware/tooling variants.

---

## 🧩 Why map to TTPs?

- **Standard language** (shared vocabulary across teams and vendors).  
- **Generality** — detect behavior rather than a single indicator that ages quickly.  
- **Prioritization** — focus on techniques with high impact for your environment.  
- **Traceability** — link incident evidence → technique → mitigations/detections.

---

## ⚙️ TTP mapping workflow (practical)

1. **Collect evidence**
   - Logs, process trees, network flows, cloud audit events, malware samples.
2. **Extract observables**
   - File hashes, commands, domains, IPs, registry keys, API calls.
3. **Hypothesis: what was the adversary trying to achieve?**
   - Initial Access, Persistence, Credential Access, Lateral Movement, Exfiltration, etc.
4. **Map observables to ATT&CK technique(s)**
   - Use ATT&CK Navigator or a lookup table.
5. **Document procedure (procedure = observed concrete steps)**
   - Commands, file paths, service names, C2 pattern, timings.
6. **Create detection/hunt**
   - Design queries and detections that generalize the technique.
7. **Feedback & tune**
   - Track false positives, refine rules, update mapping with new evidence.

---

## 🧠 Example mapping table (actionable)

| Observed evidence | Candidate ATT&CK technique | Tactic | Detection idea |
|-------------------|---------------------------|--------|----------------|
| `powershell -nop -w hidden -EncodedCommand ...` | T1059.001 — PowerShell | Execution | Detect base64 / encoded PowerShell invocations longer than X chars |
| Outbound periodic HTTP to random subdomain `*.example.com` | T1071.001 / T1071 — Application Layer Protocols | C2 / Command & Control | Identify regular beacon intervals; unusual SNI patterns |
| Creation of new service `svchostx` and autorun registry key | T1547 / T1112 (persistence) | Persistence | Detect new services installed by non-admin user or with unusual binary path |
| `Invoke-Mimikatz` strings, lsass access | T1003 — OS Credential Dumping | Credential Access | EDR alerts for lsass memory read, suspicious process injecting into lsass |
| Mass `COPY` to external SMB share at off-hours | T1041 — Exfiltration over C2 channel | Exfiltration | Monitor large outbound SMB transfers, unusual destination hosts |

---

## 🔧 Detection/hunt design patterns

- **Time-based behavior:** beaconing periodicity, out-of-hours activity.  
- **Anomalous parent-child relationships:** signed binary spawning `cmd.exe` → flag.  
- **Rare/process delta from baseline:** new service, new scheduled task.  
- **Cross-signal correlation:** suspicious DNS + endpoint process + network flow.  
- **TTP chaining:** detect sequences (e.g., PowerShell execution → persistence write → C2 connection).

---

## 🧰 Practical examples — sample queries

> Below are *template* examples. Adapt field names & data models to your SIEM/EDR.

**Splunk (pseudo):**
```spl
# Detect encoded PowerShell usage
index=wineventlog EventCode=4688 CommandLine="*powershell* -EncodedCommand*" 
| where len(CommandLine) > 200
| stats count by host, User, CommandLine
```

Elastic / EQL (pseudo):
```eql
process where process.name == "powershell.exe" and process.args : "*-EncodedCommand*"
| sort by "@timestamp" desc
```

KQL (Azure Sentinel) (pseudo):
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "-EncodedCommand"
| where strlen(ProcessCommandLine) > 200
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ProcessCommandLine
```

🧭 Operational recommendations
- Store mapping as structured metadata in your CTI platform (ATT&CK ID, technique name, confidence, evidence refs).
- Use ATT&CK Navigator for visualization and coverage tracking.
- Maintain a “hunting library” of queries per technique (indexed by ATT&CK id).
- Track which techniques are covered by existing detections; prioritize uncovered high-risk techniques.

📚 References & tools
- MITRE ATT&CK (use the official matrix and Navigator)
- ATT&CK-to-detection community repos (maintain your own copy)
- CTI platforms (MISP/OpenCTI) to store mapping and enrichments
