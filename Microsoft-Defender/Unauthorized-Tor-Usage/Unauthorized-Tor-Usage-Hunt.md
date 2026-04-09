<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation]

## Platforms and Languages Leveraged
- Windows 10 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- TOR Browser

## Scenario

Management suspects that an employee may be using TOR Browser to bypass network monitoring and access restricted or anonymous services from a corporate-managed endpoint. Recent telemetry review prompted a focused threat hunt to determine whether TOR was downloaded, installed, launched, and used on the system. If any TOR-related activity is confirmed, management should be notified.

### High-Level TOR-Related IoC Discovery Plan

- Check `DeviceFileEvents` for TOR-related files written to disk
- Check `DeviceProcessEvents` for TOR installer execution and browser component launches
- Check `DeviceNetworkEvents` for outbound connections initiated by `tor.exe` or `firefox.exe` over ports commonly associated with TOR activity
- Check for suspicious user-created artifacts associated with the activity, such as `tor-shopping-list.txt`

---

## Investigation Steps

### 1. Reviewed the `DeviceFileEvents` Table for TOR-Related File Activity

A search of `DeviceFileEvents` on `windows-vm-kwb` for filenames containing the string `tor` identified multiple TOR-related file events. Telemetry showed the TOR installer appearing in the Downloads directory, followed by TOR-related files and shortcuts being created on the desktop. Additional evidence showed the later creation of a suspicious user-generated file named `tor-shopping-list.txt`.

The earliest TOR-related file activity observed in this query appeared at `Apr 3, 2026 9:04:59 AM`, and the later suspicious text artifact was created at `Apr 3, 2026 9:23:10 AM`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "windows-vm-kwb"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256
```

![alt text](<Screenshot 2026-04-08 215541.png>)

---

### 2. Reviewed the `DeviceProcessEvents` Table for Silent TOR Installation

A search of `DeviceProcessEvents` identified direct execution of the TOR installer by account `employee77` on `windows-vm-kwb`. Telemetry showed `tor-browser-windows-x86_64-portable-15.0.8.exe` executing from the Downloads folder with the `/S` flag, indicating a silent installation.

This activity was observed at `Apr 3, 2026 9:08:01 AM`.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-kwb"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
```

![alt text](<Screenshot 2026-04-08 220357.png>)

---

### 3. Reviewed the `DeviceProcessEvents` Table for TOR Browser Execution

A follow-up review of `DeviceProcessEvents` identified execution of `tor.exe` and `firefox.exe` from the installed TOR Browser directory on the desktop. This indicated that the browser components were launched after installation and were not merely present on disk.

Multiple related process creation events were observed, including activity at `Apr 3, 2026 9:17:28 AM`, `9:17:29 AM`, and `9:18:11 AM`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "windows-vm-kwb"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
| order by Timestamp desc
```

![alt text](<Screenshot 2026-04-08 221139.png>)

---

### 4. Reviewed the `DeviceNetworkEvents` Table for TOR-Related Network Connections

A review of `DeviceNetworkEvents` showed network connections initiated by `tor.exe` and `firefox.exe` from the TOR Browser installation path on `windows-vm-kwb`. Observed connections included activity over ports `9001`, `9150`, `80`, and `443`, which is consistent with TOR-related communications and browser usage.

Examples of observed activity included:
- `Apr 3, 2026 9:09:25 AM` — `ConnectionSuccess` to remote IP `143.20.185.152` over port `9001` initiated by `tor.exe`
- `Apr 3, 2026 9:09:23 AM` — `ConnectionSuccess` to remote IP `171.25.193.9` over port `80` initiated by `tor.exe`
- `Apr 3, 2026 9:09:22 AM` — `ConnectionSuccess` to `127.0.0.1` over port `9150` initiated by `firefox.exe`

These events confirmed that TOR-related processes were not only launched, but also actively establishing network connections.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "windows-vm-kwb"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

![alt text](<Screenshot 2026-04-08 223037.png>)

---

### 5. Reviewed the `DeviceFileEvents` Table for Suspicious User-Created TOR Artifact

A focused search of `DeviceFileEvents` identified the creation of `tor-shopping-list.txt` on the desktop of `windows-vm-kwb`. The initiating process was `notepad.exe`, which supports the conclusion that this was a user-created text artifact rather than a system-generated file.

This event occurred at `Apr 3, 2026 9:23:10 AM`.

**Query used to locate event:**

```kql
DeviceFileEvents
| where DeviceName == "windows-vm-kwb"
| where FileName contains "shopping-list.txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

<img width="1153" height="692" alt="Screenshot 2026-04-08 223446" src="https://github.com/user-attachments/assets/71d032eb-1de0-4f22-a6d9-4d7b164b5223" />

---

## Chronological Event Timeline

### 1. TOR Installer Appeared on Disk
- **Timestamp:** `Apr 3, 2026 9:04:59 AM`
- **Event:** TOR-related file activity began in the user's Downloads directory.
- **Observed Artifact:** `tor-browser-windows-x86_64-portable-15.0.8.exe`
- **Path:** `C:\Users\Employee77\Downloads\`

### 2. Silent TOR Installation Executed
- **Timestamp:** `Apr 3, 2026 9:08:01 AM`
- **Event:** `employee77` executed the TOR installer in silent mode.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.8.exe /S`
- **Path:** `C:\Users\Employee77\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 3. TOR-Related Network Activity Observed
- **Timestamp:** `Apr 3, 2026 9:09:22 AM` to `9:09:25 AM`
- **Event:** TOR-related processes initiated successful and failed network connections over ports associated with TOR usage.
- **Notable Connections:**
  - `127.0.0.1:9150` via `firefox.exe`
  - `171.25.193.9:80` via `tor.exe`
  - `143.20.185.152:9001` via `tor.exe`

### 4. TOR Browser Components Launched
- **Timestamps:** `Apr 3, 2026 9:17:28 AM`, `9:17:29 AM`, and `9:18:11 AM`
- **Event:** `tor.exe` and `firefox.exe` were launched from the installed TOR Browser directory.
- **Path:** `C:\Users\Employee77\Desktop\Tor Browser\Browser\...`

### 5. Suspicious User Artifact Created
- **Timestamp:** `Apr 3, 2026 9:23:10 AM`
- **Event:** `tor-shopping-list.txt` was created on the user's desktop.
- **Initiating Process:** `notepad.exe`
- **Path:** `C:\Users\Employee77\Desktop\tor-shopping-list.txt`

---

## Summary

Threat hunting telemetry from Microsoft Defender for Endpoint confirmed unauthorized TOR-related activity on endpoint `windows-vm-kwb` associated with account `employee77`. Evidence showed TOR-related files being written to disk, silent execution of the TOR installer, subsequent launches of `tor.exe` and `firefox.exe` from the installed TOR Browser directory, and outbound network connections consistent with TOR usage. The creation of `tor-shopping-list.txt` via `notepad.exe` added a suspicious user-generated artifact to the overall activity timeline.

Taken together, the file, process, and network telemetry support the conclusion that TOR Browser was installed and used on the endpoint.

---

## Response Taken

Unauthorized TOR usage was confirmed on `windows-vm-kwb` by account `employee77` based on supporting file, process, and network telemetry. The device was isolated, and management was notified for follow-up and further review.

---
