# Threat-Hunting-Scenario-EmberForge-Source-Leak

<img width="1121" height="860" alt="image" src="https://github.com/user-attachments/assets/a689db63-bb18-4ae8-b644-c8ddf063ae3e" />


**Participant:** Kai Gallette 

**Date:** 4-6-26
## Platforms and Languages Leveraged

**Platforms:**
- Microsoft Sentinel
- Log Analytics Workspace
- Windows endpoints
- Sysmon and Windows Security logs via custom table

**Languages/Tools:**
- Kusto Query Language (KQL)
- Microsoft Sentinel Logs
- Sysmon Event Analysis
- Windows Security Event Analysis

---

## Scenario

EmberForge Studios, a game development subsidiary, suffered a multi-stage compromise involving initial user execution, payload deployment, command-and-control activity, privilege escalation, credential dumping, lateral movement, domain compromise, persistence, exfiltration, and anti-forensics.

The investigation centered on telemetry stored in the custom Sentinel table `EmberForgeX_CL`, containing Sysmon and Windows Security event data from multiple hosts in the `emberforge.local` domain. The defined investigation window was **2026-01-30 21:00 UTC through 2026-01-31 00:00 UTC**, with the key caveat that **`TimeGenerated` reflected ingestion time rather than true event time**. All time-based analysis relied on **`UtcTime_s`**.

The hunt revealed that the intrusion began with a targeted delivery to a workstation used by **Lisa Martin (`lmartin`)**, where a malicious DLL named `review.dll` was executed through `rundll32.exe` from drive `D:`, strongly suggesting mounted image delivery. The attacker established persistence, communicated with external infrastructure, compressed and exfiltrated development data to MEGA using `rclone.exe`, escalated privileges through a `fodhelper.exe` UAC bypass, dumped LSASS, laterally moved to a server and Domain Controller, extracted `ntds.dit` through Volume Shadow Copy abuse, created a backdoor domain account, installed remote access tooling, and cleared key event logs on the DC.

This report documents the investigation flag by flag, preserving the original question context, reasoning, KQL used, answer, and evidence handling notes.

---

## Threat Hunting Process

### Flag 1 – Target Directory

**Question:**  
CISO: "I have a board meeting in 4 hours. Before I care about how they got in, I need to know what they took and where it went. Legal needs the scope for breach notification."

The attacker needed to package data before stealing it. The compression commands reveal exactly what they were targeting. What directory was the source of the stolen data?

**Format:** Full path (e.g., `C:\folder\subfolder`)

**Objective:** Identify the source directory the attacker staged for theft.

**Reasoning:** Compression and exfiltration commands frequently reveal the exact source path of targeted data. Reviewing process creation events involving archiving and upload tooling exposes the path referenced in attacker commands.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("Compress-Archive", "7z", "rclone")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/97729ab6-cee7-43f9-aa6d-e5b8677577ca" />



**Answer:** `C:\GameDev`

**Evidence Type:** Direct evidence

---

### Flag 2 – Exfil Destination

**Question:**  
The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details. What cloud provider received the data?

**Format:** Provider name

**Objective:** Identify the attacker’s cloud exfiltration provider.

**Reasoning:** The attacker’s exfiltration command explicitly identified the destination remote and service configuration. Reviewing the command line for `rclone.exe` revealed the provider name.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "rclone"
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/ce03ce73-2249-4c40-9bb8-bf372b41cc5b" />


**Answer:** `MEGA`

**Evidence Type:** Direct evidence

---

### Flag 3 – Attacker Attribution

**Question:**  
Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line. What email account was used to authenticate to the cloud service?

**Format:** `email@domain.tld`

**Objective:** Identify the attacker email account used for MEGA authentication.

**Reasoning:** The attacker exposed authentication details both in the `rclone` command line and in commands used to build the configuration file.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("mega-user", "user = ")
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/7b21ff98-60ca-437b-bf59-e18fd00afcf4" />


**Answer:** `jwilson.vhr@proton.me`

**Evidence Type:** Direct evidence

---

### Flag 4 – Domain Compromise Evidence

**Question:**  
This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file. This file contains every credential in the domain. What was it?

**Format:** `filename.ext`

**Objective:** Identify the locked domain credential store accessed on the DC.

**Reasoning:** Shadow copy abuse on a Domain Controller commonly precedes theft of the Active Directory database. Review of wrapped remote execution commands showed direct copying of the file from a shadow copy path.

```kql
EmberForgeX_CL
| where EventCode_s == "7045" or EventCode_s == "1"
| where Raw_s has "ntds.dit" or CommandLine_s has "ntds.dit"
| project UtcTime_s, Computer, CommandLine_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="2048" height="691" alt="image" src="https://github.com/user-attachments/assets/0dd2dcc8-f6ae-4735-8ce6-9ad8fd3f8ca6" />


**Answer:** `ntds.dit`

**Evidence Type:** Direct evidence

---

### Flag 5 – Exfil Tool

**Question:**  
CISO: "I need to understand the exfiltration path. What tools did they use? Where did they stage from? Can we confirm this was the only way data left the network?"

Data does not always leave from the machine it was found on. Check all hosts.

A cloud synchronisation tool was used to upload data externally. This tool is legitimate software commonly abused by threat actors. It was executed multiple times, not all successfully.

**Format:** `filename.exe`

**Objective:** Identify the legitimate cloud sync tool used for exfiltration.

**Reasoning:** Repeated process execution events showed the attacker invoking the same external sync utility for version checks, configuration checks, and data transfer attempts.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "rclone" or Image_s has "rclone"
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/96f40523-2928-4c0d-8b71-33655292f595" />


**Answer:** `rclone.exe`

**Evidence Type:** Direct evidence

---

### Flag 6 – Exfil Destination IP

**Question:**  
The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3). What IP address received the stolen data?

**Format:** IP address

**Objective:** Identify the destination IP used during exfiltration.

**Reasoning:** Sysmon network connection events tied to `rclone.exe` exposed the external destination contacted during upload.

```kql
EmberForgeX_CL
| where EventCode_s == "3"
| where Image_s has "rclone.exe"
| project UtcTime_s, Computer, Image_s, DestinationIp_s, DestinationPort_s, DestinationHostname_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1611" height="333" alt="image" src="https://github.com/user-attachments/assets/67ecc71e-648e-46e7-a800-38927bd42323" />


**Answer:** `66.203.125.15`

**Evidence Type:** Direct evidence

---

### Flag 7 – Attacker Credential Exposure

**Question:**  
The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution method exposed credentials far more recklessly than the others. Compare all executions and find the plaintext password.

**Format:** Plaintext password

**Objective:** Recover the plaintext password exposed in the exfiltration command.

**Reasoning:** One `rclone` command line included both the MEGA username and password in plaintext rather than relying only on the configuration file.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "mega-pass"
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/0a8547cc-7d73-40fc-a503-f9e8308cee7b" />


**Answer:** `Summer2024!`

**Evidence Type:** Direct evidence

---

### Flag 8 – Archive Method

**Question:**  
Before exfiltration, the stolen data was compressed into an archive. The attacker used a built-in OS capability rather than third-party tools. This is a Living Off The Land technique. What cmdlet created the archive?

**Format:** PowerShell cmdlet name

**Objective:** Identify the built-in cmdlet used to compress stolen data.

**Reasoning:** The process creation logs showed a PowerShell command using a native compression cmdlet to create the staging archive.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "Compress-Archive"
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/40efe34a-fe4e-40d5-9f8b-a0466013a437" />


**Answer:** `Compress-Archive`

**Evidence Type:** Direct evidence

---

### Flag 9 – Staging Server

**Question:**  
The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

**Format:** `subdomain.domain.tld`

**Objective:** Identify the attacker-controlled staging infrastructure.

**Reasoning:** Both workstation and server download commands pointed to the same external host used to deliver tooling such as `update.exe` and `AnyDesk.exe`.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("http://", "https://", "IWR", "certutil")
| where CommandLine_s has "cloud-endpoint.net"
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="2048" height="422" alt="image" src="https://github.com/user-attachments/assets/3349cb39-52d1-460f-a954-a5dbdcef5ec7" />


**Answer:** `sync.cloud-endpoint.net`

**Evidence Type:** Direct evidence

---

### Flag 10 – Malicious File

**Question:**  
CISO: "How did they get in? I need to know if Lisa was targeted specifically or if this was opportunistic. Do we need to alert the rest of the team?"

Work backwards. Trace the process chain to the very first malicious execution.

The incident started with Lisa opening something from her desktop. Find the earliest malicious process creation event on the workstation. A Windows utility was used to load a file that does not belong in a normal user workflow.

**Format:** `filename.extension`

**Objective:** Identify the malicious file first executed by Lisa.

**Reasoning:** Reviewing the earliest suspicious `rundll32.exe` process creation on Lisa’s workstation revealed the DLL loaded through the Windows LOLBin.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "review.dll" or (Image_s has "rundll32.exe" and User_s has "lmartin")
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="2858" height="460" alt="image" src="https://github.com/user-attachments/assets/9a3690e7-abc7-473f-b5e2-4cd011649053" />



**Answer:** `review.dll`

**Evidence Type:** Direct evidence

---

### Flag 11 – Delivery Vector

**Question:**  
Look at the full path of the malicious file. The drive letter is significant. If the file is not on C:, consider how it got there. Mounted disk images (ISO, IMG, VHD) appear as virtual drives and bypass certain Windows security protections.

**Format:** Drive letter (e.g., `D:`)

**Objective:** Identify the suspicious drive letter used by the malicious DLL.

**Reasoning:** The DLL path from the initial execution event showed the payload was loaded from a non-`C:` drive, consistent with mounted image delivery.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "review.dll"
| project UtcTime_s, CommandLine_s
```

**Artifact:**  
<img width="2858" height="460" alt="image" src="https://github.com/user-attachments/assets/20eed94c-1914-4167-a020-686b468a9f0f" />


**Answer:** `D:`

**Evidence Type:** Direct evidence

---

### Flag 12 – Compromised User

**Question:**  
The User field in process creation events tells you which account executed the payload. This is patient zero.

**Format:** username

**Objective:** Identify the compromised user who executed the initial payload.

**Reasoning:** The malicious `rundll32.exe` execution event included the user context in `User_s`.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "review.dll"
| project UtcTime_s, User_s, CommandLine_s
```

**Artifact:**  
<img width="2858" height="460" alt="image" src="https://github.com/user-attachments/assets/d5de67c0-f7b5-4d55-85b6-151a42b6888c" />


**Answer:** `lmartin`

**Evidence Type:** Direct evidence

---

### Flag 13 – Execution Chain

**Question:**  
Every process has a parent, and that parent has a parent. Trace the full execution chain from the user action through to the malicious file being loaded.

**Format:** `parent.exe > child.exe > loaded_file`

**Objective:** Reconstruct the initial execution chain.

**Reasoning:** The initial malicious event showed Explorer launching `rundll32.exe`, which in turn loaded `review.dll`.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "review.dll"
| project UtcTime_s, ParentImage_s, Image_s, CommandLine_s
```

**Artifact:**  
<img width="2858" height="460" alt="image" src="https://github.com/user-attachments/assets/ddb4199e-0401-488b-8d3f-603a71153b29" />


**Answer:** `explorer.exe > rundll32.exe > review.dll`

**Evidence Type:** Direct evidence

---

### Flag 14 – Delivery Unpacking

**Question:**  
Before the malicious DLL was loaded, the user opened a downloaded archive. A compression tool extracted its contents to a folder in the user's profile. This extraction step came before the DLL execution.

**Format:** `process.exe > folder_path`

**Objective:** Identify the unpacking tool and extraction folder preceding execution.

**Reasoning:** A 7-Zip GUI extraction event showed a user archive being unpacked into a folder under Lisa’s Downloads path before the DLL launch.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "7zG.exe" or CommandLine_s has "EmberForge_Review"
| project UtcTime_s, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="3323" height="1099" alt="image" src="https://github.com/user-attachments/assets/3563d106-940b-46c2-b3b3-987cc80e79b4" />


**Answer:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`

**Evidence Type:** Direct evidence

---

### Flag 15 – Dropped Payload

**Question:**  
CISO: "A DLL loaded from a mounted drive. That is an ISO delivery. This was not opportunistic. Someone packaged a payload specifically for Lisa, named it to look like a project review file, and delivered it in a format that bypasses our SmartScreen protections. Everything you have found so far tells me what happened after the infection and how it started. Now I need you to tell me how far they got. What ran on that workstation? What is it talking to? Workstation access is bad. Lateral movement is worse. Domain compromise is a different conversation entirely. Show me the scope."

CISO: "What exactly was running on Lisa's machine? Is it still active? I need to know what infrastructure the attacker is using so we can start blocking."

Shortly after the initial DLL execution, a new executable appeared in a world-writable directory on the workstation. This became the attacker's primary tool for the rest of the operation.

**Format:** Full path (e.g., `C:\folder\file.exe`)

**Objective:** Identify the main malware/beacon dropped after the initial DLL execution.

**Reasoning:** Process creation and later child process relationships repeatedly pointed back to the same executable in `C:\Users\Public\`.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "update.exe" or Image_s has "update.exe"
| project UtcTime_s, Computer, User_s, Image_s, CommandLine_s, ParentImage_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1286" height="298" alt="image" src="https://github.com/user-attachments/assets/16651926-f515-4230-811f-d3f42e42dcfe" />


**Answer:** `C:\Users\Public\update.exe`

**Evidence Type:** Direct evidence

---

### Flag 16 – C2 Domain

**Question:**  
The malware needs to communicate with the attacker. Sysmon EventCode 22 captures every DNS query a process makes. The domain will look designed to blend in with legitimate cloud traffic.

**Format:** `subdomain.domain.tld`

**Objective:** Identify the malware’s command-and-control domain.

**Reasoning:** DNS query events tied to the malicious execution chain repeatedly resolved a cloud-themed domain distinct from the staging host.

```kql
EmberForgeX_CL
| where EventCode_s == "22"
| where QueryName_s has "cloud-endpoint.net"
| project UtcTime_s, Computer, Image_s, QueryName_s, User_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1002" height="337" alt="image" src="https://github.com/user-attachments/assets/2c3169b8-84d4-4fd2-a3d4-9e612018759a" />


**Answer:** `cdn.cloud-endpoint.net`

**Evidence Type:** Direct evidence

---

### Flag 17 – Primary C2 IP

**Question:**  
DNS queries resolve domains to IP addresses. The QueryResults field inside the EventCode 22 raw XML contains the resolved IPs. You will need to parse Raw_s.

**Format:** IP address

**Objective:** Identify the primary C2 IP associated with the malware DNS resolution.

**Reasoning:** Parsing the raw Sysmon DNS event exposed multiple resolved IPs for the C2 domain. The accepted flag answer used the primary IP extracted from the query results.

```kql
EmberForgeX_CL
| where EventCode_s == "22"
| where QueryName_s == "cdn.cloud-endpoint.net"
| extend QueryResults = extract(@"<Data Name='QueryResults'>([^<]+)</Data>", 1, Raw_s)
| project UtcTime_s, QueryName_s, QueryResults
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="734" height="263" alt="image" src="https://github.com/user-attachments/assets/47cc1e2c-87cb-4e32-9fbb-1b00a98b5b2b" />


**Answer:** `104.21.30.237`

**Evidence Type:** Direct evidence with note that multiple resolved IPs were observed

---

### Flag 18 – Injection Chain

**Question:**  
The attacker injected code from one process into another to hide. Sysmon EventCode 8 (CreateRemoteThread) captures this. Trace the injection chain.

**Format:** `source.exe > target.exe`

**Objective:** Identify the first malicious process injection chain.

**Reasoning:** Reviewing EventCode 8 activity distinguished malicious injection from routine Windows process activity. The accepted injection chain was from `rundll32.exe` into `notepad.exe`.

```kql
EmberForgeX_CL
| where EventCode_s == "8"
| project UtcTime_s, Computer, SourceImage_s, TargetImage_s, EventData_Xml_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1529" height="584" alt="image" src="https://github.com/user-attachments/assets/360e630c-0f25-460c-9171-1d2735112a05" />


**Answer:** `rundll32.exe > notepad.exe`

**Evidence Type:** Direct evidence

---

### Flag 19 – UAC Bypass Binary

**Question:**  
CISO: "Did they get admin access? If they dumped credentials, I need to know which accounts are compromised. Every compromised account is a password reset."

Certain Windows executables are trusted to auto-elevate without a UAC prompt. Attackers hijack what these binaries execute via registry modifications. Look for registry changes (EventCode 13) followed immediately by a trusted binary execution.

**Format:** `filename.exe`

**Objective:** Identify the auto-elevated binary abused for UAC bypass.

**Reasoning:** Registry modifications under the `ms-settings` handler were followed by execution of the trusted auto-elevated Windows binary associated with a classic bypass technique.

```kql
EmberForgeX_CL
| where EventCode_s in ("13","1")
| where TargetObject_s has "ms-settings" or CommandLine_s has "fodhelper" or Image_s has "fodhelper"
| project UtcTime_s, EventCode_s, Image_s, CommandLine_s, TargetObject_s, Details_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="760" height="167" alt="image" src="https://github.com/user-attachments/assets/90332f2e-59ca-4a2b-866f-e37e8eebd3f7" />


**Answer:** `fodhelper.exe`

**Evidence Type:** Direct evidence

---

### Flag 20 – Registry Bypass Enabler

**Question:**  
The UAC bypass works by creating a specific registry value that redirects execution. Two modifications were made in quick succession. One set the payload path. The other enables the hijack. What is that value name?

**Format:** Value name

**Objective:** Identify the registry value used to enable the UAC bypass.

**Reasoning:** EventCode 13 registry modifications clearly showed the hijack path under the `ms-settings\shell\open\command` key and the enabling value.

```kql
EmberForgeX_CL
| where EventCode_s == "13"
| where TargetObject_s has "ms-settings\\shell\\open\\command"
| project UtcTime_s, TargetObject_s, Details_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="827" height="311" alt="image" src="https://github.com/user-attachments/assets/436ef7c2-f11a-4e44-98e8-7cc702099d1f" />


**Answer:** `DelegateExecute`

**Evidence Type:** Direct evidence

---

### Flag 21 – Stable Injection Chain

**Question:**  
After the UAC bypass, the elevated beacon performed a second injection for long-term stability. The source process was different from the first injection, and the target was running in a completely different security context.

**Format:** `source.exe > target.exe (CONTEXT)`

**Objective:** Identify the later SYSTEM-context injection chain.

**Reasoning:** EventCode 8 showed the attacker’s malware injecting into a SYSTEM process to stabilize elevated execution after privilege escalation.

```kql
EmberForgeX_CL
| where EventCode_s == "8"
| where SourceImage_s has "update.exe" or TargetImage_s has "spoolsv.exe"
| project UtcTime_s, SourceImage_s, TargetImage_s, EventData_Xml_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1543" height="362" alt="image" src="https://github.com/user-attachments/assets/5ebec1f6-106a-41aa-b4e2-7083c14a2268" />


**Answer:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`

**Evidence Type:** Direct evidence

---

### Flag 22 – Credential Dumping Process

**Question:**  
LSASS holds credentials for every logged-in user. The attacker dumped its memory to disk. The dumping tool used direct syscalls to bypass API monitoring. You will NOT find ProcessAccess events (EventCode 10) for LSASS. What process created the dump file?

**Format:** `filename.exe`

**Objective:** Identify the process that wrote the LSASS dump.

**Reasoning:** File creation events for the dump file path directly identified the creating process image.

```kql
EmberForgeX_CL
| where EventCode_s == "11"
| where TargetFilename_s has "lsass.dmp"
| project UtcTime_s, Computer, Image_s, TargetFilename_s, User_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="976" height="373" alt="image" src="https://github.com/user-attachments/assets/2b8e3e1a-f1de-4414-a8d1-6e2ef85d7615" />


**Answer:** `update.exe`

**Evidence Type:** Direct evidence

---

### Flag 23 – Dump Location

**Question:**  
You identified the process. Now find where it wrote the output. File creation events (EventCode 11) track every file written to disk. Where was the credential dump written?

**Format:** Full path (e.g., `C:\folder\file.ext`)

**Objective:** Identify the LSASS dump file path.

**Reasoning:** The same file creation event used to identify the process also exposed the output location on disk.

```kql
EmberForgeX_CL
| where EventCode_s == "11"
| where TargetFilename_s has "lsass"
| project UtcTime_s, TargetFilename_s, Image_s
```

**Artifact:**  
<img width="569" height="285" alt="image" src="https://github.com/user-attachments/assets/f6cc1959-d8f1-49a3-a99c-5c8a5e0346d7" />


**Answer:** `C:\Windows\System32\lsass.dmp`

**Evidence Type:** Direct evidence

---

### Flag 24 – User Enumeration

**Question:**  
CISO: "What do they know about our environment? If they mapped the domain, assume they know everything."

The first command in the discovery sequence queries all user accounts in the domain.

**Format:** Full command as logged

**Objective:** Identify the attacker’s first domain user enumeration command.

**Reasoning:** Reviewing process creation activity for common domain reconnaissance commands revealed the initial user discovery step.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("net user /domain", "dsquery user", "Get-ADUser")
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="722" height="202" alt="image" src="https://github.com/user-attachments/assets/438b6dfe-69e8-41a2-b953-08fd38e11524" />


**Answer:** `net user /domain`

**Evidence Type:** Direct evidence

---

### Flag 25 – Privilege Enumeration

**Question:**  
Immediately after listing users, the attacker queried a specific group to identify who has the highest level of access.

**Format:** Full command as logged

**Objective:** Identify the domain group enumeration command used to find high-privilege accounts.

**Reasoning:** After enumerating users, the attacker checked the membership of the most critical built-in admin group.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "Domain Admins"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1405" height="310" alt="image" src="https://github.com/user-attachments/assets/70c5b8a0-5d06-4084-a480-dd05a303cb5c" />


**Answer:** `net group "Domain Admins" /domain`

**Evidence Type:** Direct evidence

---

### Flag 26 – Infrastructure Mapping

**Question:**  
The final discovery command locates critical infrastructure. The attacker needs to know where to go next.

**Format:** Full command as logged

**Objective:** Identify the command used to locate domain controllers.

**Reasoning:** The attacker followed user and privilege discovery with infrastructure mapping to identify the next target in the environment.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "nltest" or CommandLine_s has "dclist"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="782" height="311" alt="image" src="https://github.com/user-attachments/assets/cadf5c8b-5bca-4b11-83af-d0855acc482d" />


**Answer:** `nltest /dclist:emberforge.local`

**Evidence Type:** Direct evidence

---

### Flag 27 – Tool Staging Share

**Question:**  
CISO: "How many machines are compromised? I need to know the containment scope before I authorise any remediation."

Lateral movement leaves traces on BOTH the source and destination hosts. Check both.

Before moving laterally, the attacker set up the workstation as a distribution point. A network share was created.

**Format:** Full command as logged

**Objective:** Identify the share creation command used to stage tools.

**Reasoning:** The attacker exposed a world-writable local folder as a network share to distribute tooling to other systems.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "net share"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="960" height="199" alt="image" src="https://github.com/user-attachments/assets/8155269f-bd46-4e9f-9f0e-a208ad3252b8" />


**Answer:** `cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"`

**Evidence Type:** Direct evidence

---

### Flag 28 – Firewall Manipulation

**Question:**  
The workstation's firewall was blocking inbound connections needed for lateral movement. A rule was added. What name was given to the firewall rule?

**Format:** Rule name

**Objective:** Identify the inbound firewall rule created to enable movement.

**Reasoning:** The attacker used `netsh advfirewall` to allow inbound SMB traffic through the workstation firewall.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "netsh advfirewall firewall add rule"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1227" height="203" alt="image" src="https://github.com/user-attachments/assets/8b59eabb-24f5-4796-b2a6-946551d3b9a5" />


**Answer:** `SMB`

**Evidence Type:** Direct evidence

---

### Flag 29 – Post-Escalation Parent

**Question:**  
After the beacon migrated to a SYSTEM process, all subsequent attacker commands on the workstation were executed as children of that process. Look at the parent process of the lateral movement commands (share creation, file copies, firewall changes).

**Format:** `filename.exe`

**Objective:** Identify the SYSTEM process that parented later attacker actions.

**Reasoning:** After stable injection, the attacker’s later actions on the workstation originated as children of the compromised SYSTEM process.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("net share", "copy ", "netsh advfirewall")
| project UtcTime_s, CommandLine_s, ParentImage_s, User_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="798" height="394" alt="image" src="https://github.com/user-attachments/assets/08160bba-ee9b-4b72-803f-8e2b6a4d7af2" />


**Answer:** `spoolsv.exe`

**Evidence Type:** Direct evidence / confirm with artifact if available

---

### Flag 30 – Beacon Distribution

**Question:**  
The attacker pushed their primary tool to the server via Windows admin shares (C$). What was the full command?

**Format:** Full command as logged

**Objective:** Identify the exact command used to copy the beacon to the server.

**Reasoning:** The attacker used a simple command-line copy through the server’s administrative share.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "\\C$" and CommandLine_s has "update.exe"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1071" height="246" alt="image" src="https://github.com/user-attachments/assets/933828b1-103c-46c2-a748-858dbcad4b2e" />


**Answer:** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`

**Evidence Type:** Direct evidence

---

### Flag 31 – LOLBin Tool Staging

**Question:**  
On the server, a built-in Windows utility was abused to download tools from the attacker's staging infrastructure. What utility was used, and what was the full URL it downloaded from?

**Format:** `utility.exe > URL`

**Objective:** Identify the LOLBin and staging URL used on the server.

**Reasoning:** Remote execution on the server created temporary services that wrapped a built-in tool download command.

```kql
EmberForgeX_CL
| where EventCode_s == "1" or EventCode_s == "7045"
| where CommandLine_s has "certutil" or Raw_s has "certutil"
| project UtcTime_s, Computer, CommandLine_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="718" height="390" alt="image" src="https://github.com/user-attachments/assets/38cd8d91-e7d5-46b4-bd47-1f44620a5ee4" />


**Answer:** `certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe`

**Evidence Type:** Direct evidence

---

### Flag 32 – Remote Execution Evidence

**Question:**  
Now look at the server. The attacker used a remote execution technique that creates temporary Windows services with random names. These appear in EventCode 7045 in Raw_s. This answer is case-sensitive.

**Format:** Service name (case-sensitive)

**Objective:** Identify the temporary service used as remote execution evidence on the server.

**Reasoning:** EventCode 7045 on the server revealed multiple random service names associated with remote command execution. The accepted flag answer was the first random service in the sequence used to execute commands on the target server.

```kql
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer == "EC2AMAZ-16V3AU4.emberforge.local"
| project UtcTime_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="1541" height="526" alt="image" src="https://github.com/user-attachments/assets/033abdf2-485f-414b-a7e5-8d0f76863492" />

**Answer:** `MzLblBFm`

**Evidence Type:** Direct evidence

---

### Flag 33 – First Command on Server

**Question:**  
The remote execution technique redirects command output to temporary files. The very first attacker command on any newly compromised host is almost always the same.

**Format:** Command name only

**Objective:** Identify the first meaningful attacker command issued on the newly compromised server.

**Reasoning:** Remote-execution service wrappers embedded the executed command in `ImagePath`. The first meaningful operator command was used for identity confirmation.

```kql
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer == "EC2AMAZ-16V3AU4.emberforge.local"
| extend WrappedCommand = extract(@"echo (.*?) \^&gt;", 1, Raw_s)
| project UtcTime_s, WrappedCommand, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `whoami`

**Evidence Type:** Direct evidence

---

### Flag 34 – Failed Lateral Movement

**Question:**  
The attacker's first lateral movement method was unreliable. Authentication logs on the server show repeated failures from an internal host. Examine EventCode 4625.

**Format:** Protocol name

**Objective:** Identify the protocol or authentication method used in repeated failed lateral movement attempts.

**Reasoning:** The failed 4625 events repeatedly showed the same `AuthenticationPackageName`, revealing the authentication method used during the failed attempts.

```kql
EmberForgeX_CL
| where EventCode_s == "4625"
| where Computer == "EC2AMAZ-16V3AU4.emberforge.local"
| project UtcTime_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `NTLM`

**Evidence Type:** Direct evidence

---

### Flag 35 – DC Arrival and Credential Extraction

**Question:**  
CISO: "Tell me they did not reach the Domain Controller."

The same remote execution pattern from the server was used against the DC. Parse through the command wrapper to find the actual commands.

The attacker reached the Domain Controller and immediately began working towards the AD database. Trace the first command and the extraction tool.

**Format:** `first_command > tool.exe`

**Objective:** Identify the attacker’s first command pattern on a newly reached host and the tool used to begin AD database access on the DC.

**Reasoning:** The accepted answer combined the previously established remote-execution arrival pattern on a newly compromised host with the DC-specific extraction sequence. On the server, the first meaningful operator command was `whoami`. On the DC, the extraction sequence directly showed `vssadmin` activity used to create a shadow copy prior to AD database access.

```kql
EmberForgeX_CL
| where EventCode_s == "7045"
| where Computer in ("EC2AMAZ-16V3AU4.emberforge.local", "EC2AMAZ-EEU3IA2.emberforge.local")
| extend WrappedCommand = extract(@"echo %COMSPEC% /C (.*?) \^&gt;", 1, Raw_s)
| project UtcTime_s, Computer, WrappedCommand, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `whoami > vssadmin.exe`

**Evidence Type:** Inference based on prior confirmed evidence plus direct DC evidence

---

### Flag 36 – Backdoor Account

**Question:**  
After extracting the database, the attacker created a new account designed to blend in with legitimate service accounts.

**Format:** username

**Objective:** Identify the newly created domain backdoor account.

**Reasoning:** Account creation events and process creation commands following domain compromise exposed the service-style username chosen by the attacker.

```kql
EmberForgeX_CL
| where EventCode_s == "4720" or (EventCode_s == "1" and CommandLine_s has_any ("net user", "/add"))
| project UtcTime_s, Computer, CommandLine_s, EventData_Xml_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `svc_backup`

**Evidence Type:** Direct evidence

---

### Flag 37 – Backdoor Credentials

**Question:**  
The account creation command included the password as a command line argument. Terrible OPSEC, but captured permanently in your logs.

**Format:** Plaintext password

**Objective:** Recover the plaintext password used when the backdoor account was created.

**Reasoning:** The account creation command exposed the password directly as an argument in the command line.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("net user", "/add")
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `P@ssw0rd123!`

**Evidence Type:** Direct evidence

---

### Flag 38 – Privilege Assignment

**Question:**  
Creating an account is not enough. The attacker ran a second command to give it elevated privileges.

**Format:** Group name

**Objective:** Identify the privileged group assigned to the backdoor account.

**Reasoning:** Group membership modification events and follow-on attacker commands showed the newly created account being added to a high-privilege domain group.

```kql
EmberForgeX_CL
| where EventCode_s == "4732" or (EventCode_s == "1" and CommandLine_s has_any ("net group", "Domain Admins"))
| project UtcTime_s, Computer, CommandLine_s, EventData_Xml_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `Domain Admins`

**Evidence Type:** Direct evidence

---

### Flag 39 – Exposed Credential

**Question:**  
The attacker needed to map a network drive on the DC to access tools. The drive mapping command included authentication credentials in plain text.

**Format:** Plaintext password

**Objective:** Recover the plaintext password used in the drive mapping command.

**Reasoning:** Network drive mapping or `net use` activity on the DC exposed the credential directly in the attacker’s command line.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has_any ("net use", "/user:", "New-PSDrive", "cmdkey")
| project UtcTime_s, Computer, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `EmberForge2024!`

**Evidence Type:** Direct evidence

---

### Flag 40 – Scheduled Task

**Question:**  
CISO: "If we rebuild these machines and reset every password, are we confident they cannot get back in? I need a yes or no, and I need to know what you are basing that on."

The attacker created a scheduled task to ensure their payload survives reboots. The name was chosen to look legitimate.

**Format:** Task name

**Objective:** Identify the scheduled task name used for persistence.

**Reasoning:** The task creation commands explicitly showed the name chosen by the attacker to blend with legitimate Windows activity.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where CommandLine_s has "schtasks" and CommandLine_s has "WindowsUpdate"
| project UtcTime_s, Computer, User_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `WindowsUpdate`

**Evidence Type:** Direct evidence

---

### Flag 41 – Remote Access Tool

**Question:**  
A legitimate remote management application was silently installed for unattended access.

**Format:** Software name

**Objective:** Identify the remote access software installed by the attacker.

**Reasoning:** Tool staging and installation activity on the server clearly showed the attacker downloading and silently installing a legitimate remote access application.

```kql
EmberForgeX_CL
| where EventCode_s == "1" or EventCode_s == "7045"
| where CommandLine_s has "AnyDesk" or Raw_s has "AnyDesk"
| project UtcTime_s, Computer, CommandLine_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `AnyDesk`

**Evidence Type:** Direct evidence

---

### Flag 42 – Remote Access Configuration

**Question:**  
The attacker read and modified the remote access tool's configuration file. The commands reveal its full path.

**Format:** Full path (e.g., `C:\Path\To\config.file`)

**Objective:** Identify the configuration path used by the remote access tool.

**Reasoning:** Installation and configuration activity for AnyDesk revealed the full path referenced by the attacker for unattended remote access setup.

```kql
EmberForgeX_CL
| where EventCode_s == "1" or EventCode_s == "7045"
| where CommandLine_s has "AnyDesk" or Raw_s has "AnyDesk"
| project UtcTime_s, Computer, CommandLine_s, Raw_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
`[artifact here]`

**Answer:** `C:\ProgramData\AnyDesk`

**Evidence Type:** Direct evidence

---

### Flag 43 – Anti-Forensics Tool

**Question:**  
CISO: "Are there gaps in our evidence? Did they try to cover their tracks?"

The attacker used a built-in Windows utility to clear event logs on the DC. What tool was used?

**Format:** Tool name

**Objective:** Identify the native Windows utility used to clear logs.

**Reasoning:** Process creation activity on the DC showed explicit log-clearing commands targeting core Windows event logs.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has_any ("cl", "clear-log", "clear-eventlog")
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="2367" height="725" alt="Screenshot 2026-04-06 224444" src="https://github.com/user-attachments/assets/e4ab98c6-c77d-4c12-98b4-cc55bf9213a9" />


**Answer:** `wevtutil`

**Evidence Type:** Direct evidence

---

### Flag 44 – Cleared Logs

**Question:**  
The attacker cleared more than one event log. Each clearing command targets a specific log by name. What two logs were cleared?

**Format:** Log names, comma-separated

CISO: "So we have evidence gaps on the DC where Security and System logs were wiped. Can we reconstruct what happened during those gaps using Sysmon data? Factor the evidence limitations into your final report."

**Objective:** Identify the event logs cleared by the attacker.

**Reasoning:** The command lines for `wevtutil` showed the specific log names targeted by the attacker.

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where Computer == "EC2AMAZ-EEU3IA2.emberforge.local"
| where CommandLine_s has_any ("cl", "clear-log", "clear-eventlog")
| project UtcTime_s, Computer, Image_s, CommandLine_s
| sort by todatetime(UtcTime_s) asc
```

**Artifact:**  
<img width="2367" height="725" alt="image" src="https://github.com/user-attachments/assets/ad32c90f-5d52-4509-b758-0693c6eb608a" />


**Answer:** `Security, System`

**Evidence Type:** Direct evidence

---

## Summary of Findings

| Flag # | Answer | Description |
|---|---|---|
| 1 | `C:\GameDev` | Source directory targeted for staging and exfiltration |
| 2 | `MEGA` | Cloud provider used to receive stolen data |
| 3 | `jwilson.vhr@proton.me` | Email account used for exfiltration authentication |
| 4 | `ntds.dit` | Active Directory database accessed on the Domain Controller |
| 5 | `rclone.exe` | Exfiltration utility used to transfer data externally |
| 6 | `66.203.125.15` | Destination IP observed during data exfiltration |
| 7 | `Summer2024!` | Plaintext password exposed in `rclone` command line |
| 8 | `Compress-Archive` | Native PowerShell cmdlet used to compress stolen data |
| 9 | `sync.cloud-endpoint.net` | Attacker-controlled staging infrastructure |
| 10 | `review.dll` | Malicious DLL executed on the workstation |
| 11 | `D:` | Suspicious drive letter consistent with mounted image delivery |
| 12 | `lmartin` | Compromised user and likely patient zero |
| 13 | `explorer.exe > rundll32.exe > review.dll` | Initial malicious execution chain |
| 14 | `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\` | Archive extraction preceding execution |
| 15 | `C:\Users\Public\update.exe` | Primary attacker payload/beacon on Lisa’s workstation |
| 16 | `cdn.cloud-endpoint.net` | Command-and-control domain queried by the malware |
| 17 | `104.21.30.237` | Primary resolved IP used for the accepted C2 flag answer |
| 18 | `rundll32.exe > notepad.exe` | First malicious process injection chain |
| 19 | `fodhelper.exe` | Auto-elevated binary abused for UAC bypass |
| 20 | `DelegateExecute` | Registry value used to enable the UAC bypass |
| 21 | `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` | Stable elevated injection chain |
| 22 | `update.exe` | Process that created the LSASS dump |
| 23 | `C:\Windows\System32\lsass.dmp` | LSASS dump file path |
| 24 | `net user /domain` | First user enumeration command |
| 25 | `net group "Domain Admins" /domain` | Privilege enumeration command |
| 26 | `nltest /dclist:emberforge.local` | Infrastructure discovery command for Domain Controllers |
| 27 | `cmd.exe /c "net share tools=C:\Users\Public /grant:everyone,full"` | Share created for tool staging |
| 28 | `SMB` | Firewall rule name added for inbound access |
| 29 | `spoolsv.exe` | Post-escalation parent process for later workstation actions |
| 30 | `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe` | Beacon distribution command to server |
| 31 | `certutil.exe > http://sync.cloud-endpoint.net:8080/update.exe` | LOLBin-based tool staging on server |
| 32 | `MzLblBFm` | Temporary remote execution service on server |
| 33 | `whoami` | First meaningful attacker command on the newly compromised server |
| 34 | `NTLM` | Authentication method observed in repeated failed lateral movement attempts |
| 35 | `whoami > vssadmin.exe` | Host-arrival pattern plus DC extraction-enabling tool |
| 36 | `svc_backup` | Backdoor domain account created by the attacker |
| 37 | `P@ssw0rd123!` | Plaintext password used during account creation |
| 38 | `Domain Admins` | Group assigned to grant elevated privilege to backdoor account |
| 39 | `EmberForge2024!` | Plaintext password exposed during network drive mapping |
| 40 | `WindowsUpdate` | Scheduled task created for persistence |
| 41 | `AnyDesk` | Legitimate remote access application installed for unattended access |
| 42 | `C:\ProgramData\AnyDesk` | Remote access configuration path referenced by attacker commands |
| 43 | `wevtutil` | Native utility used to clear logs on the DC |
| 44 | `Security, System` | Event logs cleared by the attacker |

---

## Response Actions

- **Containment:** Isolate all affected systems, specifically the workstation, server, and Domain Controller involved in the intrusion chain.
- **Credential Reset:** Reset credentials for `lmartin`, all privileged accounts potentially exposed through LSASS or `ntds.dit`, and remove/reset the attacker-created backdoor account.
- **Eradication:** Remove `update.exe`, `review.dll`, `rclone.exe`, `rclone.conf`, AnyDesk artifacts, scheduled tasks, firewall exceptions, and malicious shares.
- **Persistence Removal:** Delete the `WindowsUpdate` scheduled task, remove AnyDesk unattended access configuration, and revert `fodhelper` UAC bypass registry modifications.
- **Network Blocking:** Block `sync.cloud-endpoint.net`, `cdn.cloud-endpoint.net`, `66.203.125.15`, and any additional MEGA or attacker-controlled infrastructure identified during the hunt.
- **Privilege Review:** Audit membership of `Domain Admins`, remove `svc_backup`, and investigate whether additional unauthorized principals were added or modified.
- **Forensic Preservation:** Preserve Sysmon data and remaining host artifacts, especially on the DC where Security and System logs were cleared.
- **Scope Expansion:** Review all systems for identical temporary service patterns, `rclone`, AnyDesk installation traces, shadow copy abuse, and `wevtutil` execution.

---

## Lessons Learned

This hunt reinforced the importance of correlating endpoint telemetry across process creation, DNS, network, registry, file creation, service creation, and authentication events to reconstruct a multi-stage intrusion.

The initial compromise demonstrated how mounted image delivery can bypass user expectations and blend into normal workflow activity. The execution of `review.dll` through `rundll32.exe` from drive `D:` showed that careful attention to path context, parent-child process relationships, and user-driven execution is critical for identifying targeted delivery.

The attacker’s use of legitimate tools and native operating system functionality complicated detection. PowerShell `Compress-Archive`, `rclone.exe`, `certutil.exe`, `fodhelper.exe`, `schtasks.exe`, `netsh`, `vssadmin`, and `wevtutil` were all abused to support collection, exfiltration, privilege escalation, persistence, credential theft, and anti-forensics. These behaviors highlight the need for strong behavior-based detection rather than simple binary-based alerting.

Lateral movement and domain compromise were reconstructed through temporary service creation events, repeated NTLM failures, administrative share access, and shadow copy abuse on the Domain Controller. Even with evidence gaps introduced by the clearing of Security and System logs, Sysmon telemetry preserved enough process and command context to recover much of the attacker’s activity. This underscores the value of layered logging and the importance of retaining telemetry beyond traditional Windows event logs alone.

Finally, the hunt showed how attackers frequently reveal critical details through poor operational security. Plaintext passwords, staging URLs, exposed cloud credentials, task names, service names, and remote execution wrapper commands all helped accelerate reconstruction of the intrusion. Defensive teams should continue prioritizing command-line visibility, Sysmon coverage, and centralized log retention to reduce dwell time and improve post-compromise recovery.
