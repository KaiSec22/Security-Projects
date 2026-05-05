## Endpoint Logging Visibility Lab — Windows Event Logs, Sysmon, and PowerShell Detection

### Environment & Scenario Context

This lab focused on improving endpoint visibility in a Windows environment by expanding native logging, enabling PowerShell telemetry, and deploying Sysmon for richer process and system event collection. The goal was to simulate the type of endpoint logging foundation that defenders rely on for investigation, detection development, and threat hunting.

The project was built around a sequence of modules covering Sysmon deployment, Windows Event Log analysis, MITRE ATT&CK mapping, PowerShell logging, and broader detection validation. Together, these steps created a more complete logging and visibility baseline than default Windows logging alone.

---

### Detection & Logging Approach

Rather than treating endpoint logging as a single configuration task, this project approached visibility as a layered defensive process.

The workflow focused on:

- improving baseline endpoint telemetry with Sysmon
- reviewing high-value native Windows event logs
- validating visibility for suspicious administrative and attacker-like behavior
- mapping observed activity to ATT&CK techniques
- strengthening PowerShell logging for better script and command visibility
- confirming that multiple logging sources could support future detections

This structure reflects how blue teams build visibility over time: first by increasing telemetry, then by validating what can actually be observed and used during investigations.

---

### Data Sources & Tooling Reviewed

- **Microsoft Sysmon** — enhanced endpoint telemetry collection
- **Windows Event Viewer / Windows Event Logs** — native security and operational log visibility
- **PowerShell Operational Logs** — Script Block Logging and Module Logging validation
- **MITRE ATT&CK Framework** — behavior mapping for observed activity

---

### Sysmon Deployment and Visibility Expansion

The first phase of the lab focused on deploying **Microsoft Sysmon** to improve endpoint visibility beyond what standard Windows logs provide by default. After configuration, Sysmon telemetry was validated in the **Microsoft-Windows-Sysmon/Operational** log.

Testing confirmed that Sysmon successfully captured both **process creation events** and **file creation events**, which are valuable for tracing execution flow and identifying suspicious activity on an endpoint.

![Sysmon Process Creation Validation](sysmon_process_creation_validation.png)
![Sysmon File Creation Validation](sysmon_file_creation_validation.png)

*Sysmon successfully captured both process creation and file creation activity, expanding endpoint visibility beyond default Windows logging.*

**Findings:**

- Sysmon was successfully deployed to enhance endpoint telemetry
- Process creation events provided command execution visibility
- File creation events confirmed that Sysmon could capture changes to files and scripts on the host
- Sysmon created a stronger logging baseline for future detection and investigation use cases

---

### Windows Event Log Analysis

The next phase focused on reviewing native Windows logs for meaningful security and operational events. This included validating failed authentication attempts in the **Security** log and analyzing scheduled task execution through the **TaskScheduler/Operational** log.

This phase showed that even without additional tooling, Windows Event Logs can provide valuable evidence for authentication issues, persistence activity, and administrative actions.

![Failed Logon Event 4625](failed_logon_event_4625.png)
![Task Scheduler Action Completed](task_scheduler_action_completed.png)

*Native Windows logging captured both failed authentication activity and scheduled task execution, demonstrating visibility into common administrative and security-relevant events.*

**Findings:**

- Event ID **4625** provided visibility into failed logon activity
- Task Scheduler operational events showed when scheduled actions completed successfully
- Native Windows logs offered useful context for both troubleshooting and security analysis
- Baseline Windows telemetry remained valuable even when paired with enhanced logging sources like Sysmon

---

### MITRE ATT&CK Mapping

After validating the presence of useful endpoint data, the observed activity was mapped to the **MITRE ATT&CK Framework** to better translate raw events into recognizable attacker behaviors.

The lab aligned observed telemetry to techniques such as:

- **T1059 — Command and Scripting Interpreter**
- **T1053 — Scheduled Task/Job**
- **T1078 — Valid Accounts**

This phase reinforced the importance of interpreting event logs through a behavioral lens instead of viewing each event in isolation. The exercise showed how endpoint telemetry can support both direct investigation and ATT&CK-based detection development.

**Findings:**

- Native and enhanced endpoint logs could be mapped to meaningful ATT&CK techniques
- Authentication, script execution, and scheduled task activity all aligned to common attacker behaviors
- ATT&CK mapping added analytical value beyond simple event identification
- The logging stack supported both operational visibility and threat-informed analysis

---

### PowerShell Logging Enhancement

A major part of the lab focused on strengthening visibility into PowerShell usage. Because PowerShell is heavily used by both administrators and attackers, improved logging is important for distinguishing normal activity from suspicious script execution.

Validation confirmed that enhanced PowerShell telemetry was available through:

- **Event ID 4104** — Script Block Logging
- **Event ID 4103** — Module / Pipeline Logging

These logs captured both script content and execution details, improving visibility into what PowerShell was doing on the host.

![PowerShell Script Block Logging](powershell_script_block_logging_4104.png)
![PowerShell Module Logging](powershell_module_logging_4103.png)

*Enhanced PowerShell logging captured both script block content and pipeline/module-level execution details, improving visibility into command and script activity on the endpoint.*

**Findings:**

- PowerShell Script Block Logging captured executed script content
- Module and pipeline logging added deeper context about command execution
- PowerShell activity was no longer limited to simple process visibility
- Enhanced PowerShell telemetry improved the host’s detection and investigation value

---

### Detection Validation and Logging Expansion

The final phase of the project focused on confirming that the endpoint was no longer dependent on a single log source. Instead, it had layered visibility across Sysmon, native Windows Event Logs, and PowerShell operational logs.

This expanded telemetry approach improved the ability to:

- trace process execution
- observe authentication failures
- identify scheduled task behavior
- inspect PowerShell script and pipeline activity

Together, these logging improvements created a stronger detection and investigation foundation for endpoint-focused blue team work.

**Findings:**

- Visibility was established across multiple complementary log sources
- Endpoint actions could be validated through overlapping telemetry
- The environment became better suited for threat hunting and detection engineering
- Logging depth improved both troubleshooting and security analysis capability

---

### Conclusion

This project demonstrated how to build a stronger Windows endpoint visibility baseline by combining Sysmon, native Windows Event Logs, PowerShell logging, and ATT&CK-based analysis. Rather than relying on default logs alone, the lab expanded telemetry coverage and validated that suspicious behaviors could be surfaced more effectively.

By working through Sysmon deployment, event review, PowerShell logging enhancement, and MITRE mapping, the lab showed how defenders can turn raw endpoint activity into useful detection and investigation context. The result was a more mature logging foundation that better supports blue team operations, incident triage, and future detection engineering.

---

### Recommended Improvements & Operational Takeaways

- Standardize enhanced endpoint logging across all Windows systems where possible
- Use Sysmon alongside native Windows logs to improve process and system visibility
- Enable PowerShell logging in environments where script abuse is a realistic risk
- Regularly validate logging configurations with controlled simulations instead of assuming coverage exists
- Continue mapping observed telemetry to ATT&CK techniques to improve detection logic and investigation quality