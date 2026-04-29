# Threat Hunting: Internal Data Exfiltration Detection

## 1. Preparation

### Scenario

An employee named **John Doe**, working in a sensitive department, recently got put on a performance improvement plan (PIP). After displaying erratic behavior, management has raised concerns that John may be planning to steal proprietary information and then quit the company.

**Description:**

- **John** has **administrator privileges** on his device.
- He is not limited on which applications he uses.

**Task:**

- Investigate John's activities on his corporate device **`cyberclaw-vm`**.

**Goal:**

- Identify if John may attempt compression or exfiltration of sensitive data to a private drive.

---

### Components, Tools, and Technologies Employed

- **Cloud Environment:** Microsoft Azure (VM-Windows target machine)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)
  

----

## 2. Detection & Analysis

### **File Inspection**

I searched MDE's DeviceFileEvents for `.zip` file activity.

```kql
DeviceFileEvents
| where DeviceName == "cyberclaw-vm"
| where FileName endswith ".zip"
| order by Timestamp desc
```

<img alt="Image" src="https://github.com/user-attachments/assets/33a01a2e-d2fe-4632-980d-334f52288ccf" />
<br><br>

Findings: Results showed regular archiving patterns: files created and renamed inside a `backup` folder.

#### `Timestamp captured: 2026-04-24T14:41:55.3369801Z`

---

### **Process Activity Analysis**

Using the timestamp captured from the `.zip` file creation event, I queried the `DeviceProcessEvents` table for any process activity within a two-minute window to identify what may have created the archive.

```kql
let SuspiciousVM = "cyberclaw-vm";
let SpecificTime = datetime(2026-04-24T14:41:55.3369801Z);
DeviceProcessEvents
| where Timestamp between ((SpecificTime - 2m) .. (SpecificTime + 2m))
| where DeviceName == SuspiciousVM
| order by Timestamp desc
| project Timestamp, FileName, ActionType, ProcessCommandLine, InitiatingProcessCommandLine
```

<img alt="Image" src="https://github.com/user-attachments/assets/0dc81b99-941d-4e3a-87a9-06a945098338" />
<br><br>

Findings: A PowerShell script quietly installed `7zip` and then used it to compress employee data.

---

### **Network Exfiltration Path Review**

I analyzed network events within five minutes before and after the identified incident to check for any outbound connections that would indicate data exfiltration.

```kql
let SuspiciousVM = "cyberclaw-vm";
let SpecificTime = datetime(2026-04-24T14:41:55.3369801Z);
DeviceNetworkEvents
| where Timestamp between ((SpecificTime - 5m) .. (SpecificTime + 5m))
| where DeviceName == SuspiciousVM
| order by Timestamp desc
```

<img alt="Image" src="https://github.com/user-attachments/assets/202ddba1-0d22-4b09-88c3-62bb51d341ed" />
<br><br>
Findings: No outbound connections to external IP addresses, cloud storage domains, or unauthorized destinations were observed.

---

### **MITRE ATT&CK Mapping: Tactics, Techniques, and Procedures (TTPs)**

- [T1059.001 – Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

- [T1560.001 – Archive Collected Data: Archive via Utility](https://attack.mitre.org/techniques/T1560/001/)

- [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)

- [T1074.001 – Data Staged: Local Data Staging](https://attack.mitre.org/techniques/T1074/001/)

- [T1564.001 — Hide Files and Directories](https://attack.mitre.org/techniques/T1564/001/)
---

## 3. Response

Findings were reported to the employee's management regarding archive creation via PowerShell scripts. No conclusive evidence of data exfiltration was found, and monitoring remains active pending further management instructions.

---

## 4. Documentation
Findings:

- PowerShell script execution
- `7zip` installation
- Employee data compressed to `.zip`
- Archive moved to hidden folder

## 5. Improvement

- Block unauthorized tools (e.g., `7-Zip` via App Control)
- Set alerts for suspicious PowerShell execution, Zip file activity, silent installs
- Define clear isolation criteria: isolate if exfiltration is confirmed or in progress
- Develop baseline of normal archiving behavior by department/role
---
## 🧾Summary                   
The user `cyberclaw-vm` installed `7-Zip` via PowerShell, compressed employee data into a ZIP archive, and moved it to a `backup` folder in ProgramData. No data exfiltration was detected. The behavior is consistent with data staging, so findings were escalated to management and monitoring remains active.

---
## References
- [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf)
