# Microsoft Sentinel Suspicious PowerShell Analytics Rule & Incident Workflow

### Environment & Scenario Context

A Microsoft Sentinel scheduled analytics rule was created to detect suspicious PowerShell execution activity across Microsoft Defender for Endpoint telemetry. The purpose of the lab was to build a detection rule from KQL logic, configure it as a Sentinel analytics rule, generate an incident, investigate the resulting alert, validate the PowerShell activity behind the incident, and document the outcome from a detection engineering and SOC triage perspective.

The rule logic was based on the `DeviceProcessEvents` table and focused on PowerShell executions containing suspicious command-line indicators such as encoded commands, execution policy bypass, web-based retrieval behavior, and hidden or obfuscated execution patterns.

This lab was performed in a shared cyber range environment, where some activity was expected to originate from authorized system automation, Azure guest configuration, vulnerability scanning, or lab operations. Because of that, the investigation focused not only on identifying suspicious PowerShell behavior, but also on validating context and determining how the rule should be tuned before production use.

---

### Detection Approach

The detection was designed to identify PowerShell executions commonly associated with attacker behavior, payload retrieval, obfuscation, and defense evasion.

The rule focused on the following indicators:

- Encoded PowerShell commands
- PowerShell shorthand encoded command usage
- Web-based retrieval activity
- Download string usage
- Base64 decoding behavior
- Hidden PowerShell window execution
- Execution policy bypass

The detection intentionally avoided relying only on broad indicators such as normal PowerShell execution or `-NoProfile`, because those can appear frequently in legitimate administrative activity. Instead, the rule focused on stronger command-line indicators that are more relevant for SOC triage.

**ATT&CK Techniques Observed:**

- **T1059.001 — Command and Scripting Interpreter: PowerShell**
- **T1027 — Obfuscated Files or Information**
- **T1105 — Ingress Tool Transfer**

---

### Data Sources Reviewed

- `DeviceProcessEvents` — PowerShell process execution, command-line arguments, initiating process context, hostnames, and account context
- Microsoft Sentinel Analytics Rule — scheduled detection configuration and MITRE ATT&CK mapping
- Microsoft Sentinel Incident Queue — generated incident, alert count, severity, status, provider, and ownership
- Microsoft Sentinel Investigation Graph — entity relationship mapping across accounts and hosts
- Microsoft Sentinel Incident Details — evidence count, entities, tactics, techniques, closure reason, and analyst notes

---

### Analytics Rule Logic

Initial discovery showed that PowerShell activity was present in Microsoft Defender for Endpoint telemetry through the `DeviceProcessEvents` table. A focused query was then used to identify PowerShell executions containing higher-risk command-line indicators.

![Suspicious PowerShell Query Results](visuals/01_suspicious_powershell_query_results.png)

The detection was then tuned to focus on stronger suspicious indicators such as encoded command usage, execution policy bypass, web-based retrieval, base64-related behavior, and hidden window execution.

![Tuned PowerShell Detection Query](visuals/02_tuned_powershell_detection_query.png)

The final analytics rule used the following KQL logic:

    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    | where ProcessCommandLine has_any (
        "-EncodedCommand",
        "-enc",
        "DownloadString",
        "Invoke-WebRequest",
        "iwr",
        "FromBase64String",
        "WindowStyle Hidden",
        "ExecutionPolicy Bypass"
    )
    | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
    | order by Timestamp desc

A Microsoft Sentinel scheduled analytics rule was created using this query. The rule was configured to review the previous 7 days of data, generate an alert when the query returned results, and automatically create an incident for triage.

Entity mapping was configured to enrich the incident:

- **Host entity:** `DeviceName`
- **Account entity:** `InitiatingProcessAccountName`

![Analytics Rule Configuration](visuals/03_analytics_rule_configuration.png)

The completed custom analytics rule appeared under active Sentinel analytics rules as an enabled scheduled rule.

![Analytics Rule Created](visuals/04_analytics_rule_created.png)

**Findings:**

- The rule successfully used Defender process telemetry as a detection source
- The detection focused on higher-confidence suspicious PowerShell indicators
- Entity mapping was configured so hosts and accounts would appear in the incident investigation
- The rule was mapped to Execution, Defense Evasion, and Command and Control tactics

---

### Incident Generation

After the scheduled analytics rule executed, Microsoft Sentinel generated an incident titled **Suspicious PowerShell Activity Detected KWB**.

![Incident Created and Overview](visuals/05_incident_created_and_overview.png)

The incident showed a high severity rating, associated alerts, thousands of related events, and over one hundred mapped entities. This confirmed that the full detection pipeline was working:

    KQL query → Scheduled analytics rule → Alert → Sentinel incident

**Findings:**

- Sentinel successfully generated an incident from the custom analytics rule
- The incident inherited the rule description and tactics/techniques
- Host and account entities were visible in the incident overview
- The large evidence and entity count indicated that the rule matched broad activity across the shared lab environment

---

### Incident Investigation

The incident was assigned to the analyst and moved to **Active** for investigation. The full incident details page showed the incident timeline, related entities, evidence count, associated alerts, tactics and techniques, similar incidents, and top insights.

![Incident Full Details Overview](visuals/06_incident_full_details_overview.png)

The Sentinel investigation graph showed the incident connected to multiple host and account entities.

![Investigation Graph](visuals/07_investigation_graph.png)

This confirmed that the analytics rule entity mapping successfully enriched the incident. Instead of only reviewing raw query results, the incident could be investigated through a relationship-based view showing how the alert connected to hosts and accounts across the environment.

**Findings:**

- The incident contained a broad set of mapped entities
- Multiple hosts and accounts were associated with the suspicious PowerShell activity
- Entity mapping improved the quality of the investigation workflow
- The graph showed that the activity was not isolated to a single host or account

---

### Follow-up Validation

A follow-up validation query was run across the same 7-day lookback window used by the analytics rule. This helped summarize which hosts, accounts, and initiating processes contributed most heavily to the incident.

    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    | where ProcessCommandLine has_any (
        "-EncodedCommand",
        "-enc",
        "DownloadString",
        "Invoke-WebRequest",
        "iwr",
        "FromBase64String",
        "WindowStyle Hidden",
        "ExecutionPolicy Bypass"
    )
    | summarize EventCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) 
        by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
    | order by EventCount desc

![PowerShell Activity Summary](visuals/08_powershell_activity_summary.png)

The results showed that suspicious PowerShell indicators appeared across multiple systems and account contexts. The highest-volume activity was associated with system-level execution through `cmd.exe`, and additional results involved `gc_worker.exe`, which appeared consistent with Azure guest configuration or management activity.

A representative evidence query was then reviewed to inspect raw PowerShell events across the environment.

    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    | where ProcessCommandLine has_any (
        "-EncodedCommand",
        "-enc",
        "DownloadString",
        "Invoke-WebRequest",
        "iwr",
        "FromBase64String",
        "WindowStyle Hidden",
        "ExecutionPolicy Bypass"
    )
    | project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
    | order by Timestamp desc

![Representative PowerShell Evidence](visuals/09_representative_powershell_evidence.png)

The representative evidence showed suspicious PowerShell command-line patterns such as encoded command usage, execution policy bypass, and PowerShell launched through command shell or guest configuration-related processes.

**Findings:**

- Suspicious PowerShell indicators were present across multiple hosts
- Activity included encoded command usage and execution policy bypass
- Multiple events were initiated through `cmd.exe`
- Some activity appeared tied to Azure guest configuration, system automation, scanner activity, or shared lab operations
- The rule correctly detected suspicious PowerShell patterns, but the volume of results required additional context validation

---

### Detection Tuning Review

Because the incident generated a large amount of evidence, a tuning summary query was created to classify results into review categories. The purpose was to separate likely expected operational activity from events that still required analyst review.

    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    | where ProcessCommandLine has_any (
        "-EncodedCommand",
        "-enc",
        "DownloadString",
        "Invoke-WebRequest",
        "iwr",
        "FromBase64String",
        "WindowStyle Hidden",
        "ExecutionPolicy Bypass"
    )
    | extend ReviewCategory = case(
        InitiatingProcessAccountName has "nessus" or InitiatingProcessCommandLine has "nessus" or ProcessCommandLine has "nessus", "Likely scanner/service-account activity",
        InitiatingProcessFileName in~ ("gc_worker.exe", "gc_service.exe") or ProcessCommandLine has "GuestConfiguration", "Likely Azure guest configuration activity",
        InitiatingProcessAccountName == "system" and InitiatingProcessFileName == "cmd.exe", "System or lab automation context",
        "Requires analyst review"
    )
    | summarize EventCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
        by ReviewCategory, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName
    | order by EventCount desc

![Detection Tuning Summary](visuals/10_detection_tuning_summary.png)

The tuning summary showed that many high-volume results were associated with system or lab automation context, Azure guest configuration activity, and likely scanner or service-account activity. A smaller subset remained categorized as **Requires analyst review**, which showed that the tuning logic reduced noise without fully suppressing visibility into unexplained activity.

**Findings:**

- Most high-volume results were explainable through operational context
- Azure guest configuration and lab automation created repeated PowerShell activity
- Scanner or service-account behavior contributed to the alert volume
- Some events still required analyst review
- The rule was effective, but would require tuning before production deployment

---

### Incident Closure

After investigation, the incident was closed as:

**Benign Positive — Suspicious but expected**

![Incident Closure](visuals/11_incident_closure.png)

The closure notes documented that the analytics rule successfully detected suspicious PowerShell command-line indicators, including encoded command usage, execution policy bypass, and web-based retrieval patterns. Follow-up investigation showed that many high-volume results were associated with system-level execution, Azure guest configuration activity, scanner/service-account activity, or lab automation context.

No confirmed malicious activity was identified during the investigation. The recommended next step was to tune the rule to suppress known approved scanner and automation contexts while preserving detections for unexpected user accounts, unknown hosts, or unapproved PowerShell execution patterns.

**Findings:**

- The incident was investigated from creation through closure
- The detection successfully identified suspicious PowerShell behavior
- Context validation showed that much of the activity was likely expected in the shared lab environment
- The final disposition accurately reflected suspicious but expected activity
- The lab demonstrated both alert triage and detection tuning considerations

---

### Conclusion

This lab demonstrated how Microsoft Sentinel can be used to operationalize KQL detection logic into a scheduled analytics rule, generate an incident, enrich the alert with mapped entities, and support a structured SOC investigation workflow.

The analytics rule successfully detected PowerShell executions containing suspicious command-line indicators such as encoded commands, execution policy bypass, web-based retrieval behavior, and hidden or obfuscated execution patterns. Sentinel generated an incident from the rule, mapped host and account entities, and provided an investigation graph for relationship-based triage.

Follow-up validation showed that the suspicious PowerShell activity was broad across the shared cyber range environment. Many high-volume results aligned with system-level execution, Azure guest configuration activity, scanner/service-account behavior, or lab automation. Because no confirmed malicious activity was identified, the incident was closed as **Benign Positive — Suspicious but expected**.

The primary value of this lab was demonstrating the full detection engineering workflow:

    Detection logic → Sentinel analytics rule → Incident generation → Entity mapping → Investigation → Tuning review → Closure

---

### Recommended Mitigations & Improvements

- Tune the analytics rule to suppress known approved scanner/service-account activity
- Add allowlisting for expected Azure guest configuration processes where appropriate
- Preserve alert visibility for PowerShell activity from unexpected user accounts
- Prioritize alerts involving encoded PowerShell from non-system accounts or unknown hosts
- Add custom details to future Sentinel rules for command line, initiating process, and review category
- Consider creating separate rule severity levels for high-confidence suspicious PowerShell versus expected administrative automation
- Review recurring system or lab automation activity with asset owners before suppressing it
- Use watchlists for approved scanner accounts, approved automation hosts, and known management processes
- Continue mapping host and account entities so Sentinel incidents remain useful during triage
