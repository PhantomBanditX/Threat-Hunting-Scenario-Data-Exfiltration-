# Threat Hunting: Internal Data Exfiltration Detection

## 1. Preparation

### Scenario

An employee named **John Doe**, working in a sensitive department, recently got put on a performance improvement plan (PIP). After displaying erratic behavior, management has raised concerns that John may be planning to steal proprietary information and then quit the company.

**Description:**

- **John** has **administrator privileges** on his device.
- He is not limited on which applications he uses.

**Task:**

Investigate John's activities on his corporate device **`cyberclaw-vm`**.

**Goal:**

Identify if John may attempt compression or exfiltration of sensitive data to a private drive.

---

### Components, Tools, and Technologies Employed

- **Cloud Environment:** Microsoft Azure (VM-Windows target machine)
- **Threat Detection Platform:** Microsoft Defender for Endpoint (MDE)

---

## 2. Data Collection

**Tables used:**

- `DeviceFileEvents`
- `DeviceProcessEvents`
- `DeviceNetworkEvents`

---

## 3. Data Analysis

**Query 1: File Inspection**

Searched MDE's DeviceFileEvents for .zip file activity.

```kql
DeviceFileEvents
| where DeviceName == "cyberclaw-vm"
| where FileName endswith ".zip"
| order by Timestamp desc
```

<img width="1919" height="872" alt="Image" src="https://github.com/user-attachments/assets/33a01a2e-d2fe-4632-980d-334f52288ccf" />

