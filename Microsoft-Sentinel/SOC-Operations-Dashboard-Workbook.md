# Microsoft Sentinel SOC Operations Dashboard

### Environment & Scenario Context

A Microsoft Sentinel workbook was created to provide SOC-style operational visibility across the cyber range environment. The purpose of the lab was to build a reusable dashboard that could help analysts monitor incident volume, severity, status, recent detections, current triage workload, and detection trends from a centralized view.

Unlike a single-incident investigation, this lab focused on dashboarding and SOC reporting. The workbook used KQL queries against Sentinel incident data and Defender telemetry to summarize current security operations activity across a 24-hour monitoring window.

The dashboard was designed to answer common SOC questions:

- How many incidents were generated in the last 24 hours?
- What severity levels are most common?
- How many incidents are New, Active, or Closed?
- Which incidents are waiting for analyst review?
- Which incident titles or detection rules are generating the most workload?
- When are incident volumes spiking?
- Is suspicious PowerShell activity trending during the same window?

---

### Dashboard Objective

The goal of this workbook was to create a SOC operations dashboard that could support analyst triage and situational awareness.

The workbook focused on three major areas:

- **SOC Incident Overview** — high-level incident distribution by severity and status
- **Analyst Triage Queue** — recent incidents and current workload by severity/status
- **Detection Trends and Monitoring** — top incident titles, incident volume over time, and suspicious PowerShell activity trends

A 24-hour time window was used to keep the dashboard focused on current operational workload instead of overrepresenting older activity from the shared cyber range environment.

---

### Data Sources Reviewed

- `SecurityIncident` — Sentinel incident metadata, severity, status, title, owner, incident number, and creation time
- `DeviceProcessEvents` — Defender for Endpoint process telemetry used to monitor suspicious PowerShell activity
- Microsoft Sentinel Workbooks — dashboard creation and visualization
- KQL — query logic used to power workbook panels and operational metrics

---

### Workbook Structure

The workbook was organized into three main sections:

1. **SOC Incident Overview**
2. **Analyst Triage Queue**
3. **Detection Trends and Monitoring**

This structure was used to keep related panels grouped together and make the dashboard easier to interpret during analyst review.

---

### SOC Incident Overview

The first section provided a high-level view of Sentinel incident distribution across the last 24 hours.

Two panels were placed side by side:

- **Sentinel Incidents by Severity**
- **Sentinel Incidents by Status**

<img width="1409" height="478" alt="Screenshot 2026-05-14 171911" src="https://github.com/user-attachments/assets/e3b938da-4875-4fea-acbc-90c02e1ad302" />

The severity panel showed how current incidents were distributed across High, Medium, Low, and Informational severity levels.

The status panel showed how many incidents were New, Active, or Closed during the same operational window.

**Findings:**

- The majority of incidents were categorized as High or Medium severity
- Most incidents were still in a New state
- Only a small number of incidents were Active or Closed compared to the total incident volume
- The overview section provided a quick snapshot of current SOC queue pressure

The following KQL was used to summarize incidents by severity:

```kusto
SecurityIncident
| where TimeGenerated > ago(24h)
| summarize IncidentCount = count() by Severity
| order by IncidentCount desc
```

The following KQL was used to summarize incidents by status:

```kusto
SecurityIncident
| where TimeGenerated > ago(24h)
| summarize IncidentCount = count() by Status
| order by IncidentCount desc
```
---

### Analyst Triage Queue

The second section focused on analyst prioritization. This section included a recent incident queue and a severity/status workload breakdown.

The recent incident grid displayed the newest Sentinel incidents from the last 24 hours, including timestamp, title, severity, status, owner assignment, and incident number.

The workload grid summarized current incident volume by both severity and status, helping identify which types of incidents required the most immediate attention.

<img width="1709" height="554" alt="Screenshot 2026-05-14 171928" src="https://github.com/user-attachments/assets/d3c95cd2-eb63-4445-b8ca-0a37bfb94ac5" />

**Findings:**

- Several recent incidents were High severity and still New
- Many incidents were unassigned, showing they had not yet been triaged
- High/New and Medium/New incidents represented the largest portions of the active triage workload
- The section helped distinguish general incident volume from incidents requiring analyst action

The following KQL was used to populate the recent incident queue:

```kusto
SecurityIncident
| where TimeGenerated > ago(24h)
| extend OwnerName = iff(isempty(tostring(Owner.assignedTo)), "Unassigned", tostring(Owner.assignedTo))
| project TimeGenerated, Title, Severity, Status, OwnerName, IncidentNumber
| order by TimeGenerated desc
| take 10
```

The following KQL was used to summarize workload by severity and status:

```kusto
SecurityIncident
| where TimeGenerated > ago(24h)
| summarize IncidentCount = count() by Severity, Status
| order by IncidentCount desc
```

**Triage Value:**

This section was designed to help analysts quickly answer:

- Which incidents were created most recently?
- Which incidents are still unassigned?
- Which high-severity incidents are still New?
- How much of the current queue is already Active or Closed?

---

### Detection Trends and Monitoring

The third section focused on detection activity and incident trends across the 24-hour monitoring window.

This section included:

- **Top Sentinel Incident Titles**
- **Sentinel Incidents Over Time**
- **Suspicious PowerShell Activity Over Time**

<img width="1893" height="792" alt="Screenshot 2026-05-14 172002" src="https://github.com/user-attachments/assets/77527ad4-bb12-4926-8f21-943f2407ac13" />

The top incident titles panel showed which detection names or incident titles generated the most volume in the last 24 hours. This helped identify which detections were contributing most heavily to SOC workload.

The incidents-over-time panel showed hourly incident volume across the 24-hour window. This allowed analysts to identify time periods where incident generation increased or decreased.

The suspicious PowerShell activity panel provided focused visibility into PowerShell command-line patterns associated with encoded commands, execution policy bypass, web-based retrieval, and other suspicious indicators.

**Findings:**

- A small number of incident titles contributed heavily to the total incident volume
- Incident activity fluctuated across the 24-hour window, showing clear periods of increased alert generation
- Suspicious PowerShell activity appeared in multiple spikes during the same monitoring window
- The detection trend panels helped connect overall incident volume with specific suspicious activity patterns

The following KQL was used to identify top Sentinel incident titles:

```kusto
SecurityIncident
| where TimeGenerated > ago(24h)
| summarize IncidentCount = count() by Title
| top 10 by IncidentCount desc
```

The following KQL was used to chart incidents over time:

```kusto
SecurityIncident
| where TimeGenerated > ago(24h)
| summarize IncidentCount = count() by bin(TimeGenerated, 1h)
| order by TimeGenerated asc
```

The following KQL was used to chart suspicious PowerShell activity over time:

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
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
| summarize EventCount=count() by bin(Timestamp, 1h)
| order by Timestamp asc
```
---

### Dashboard Design Decisions

The workbook was intentionally organized into grouped sections instead of a long list of unrelated panels.

The final layout used the following structure:

    Microsoft Sentinel SOC Operations Dashboard

    SOC Incident Overview
    - Sentinel Incidents by Severity
    - Sentinel Incidents by Status

    Analyst Triage Queue
    - Recent Sentinel Incidents
    - Incident Workload by Severity and Status

    Detection Trends and Monitoring
    - Top Sentinel Incident Titles
    - Sentinel Incidents Over Time
    - Suspicious PowerShell Activity Over Time

This layout was chosen because each section supports a different SOC function:

- The overview section supports quick situational awareness
- The triage section supports analyst prioritization
- The detection trends section supports monitoring and reporting

---

### Conclusion

This lab demonstrated how Microsoft Sentinel workbooks can be used to create a SOC operations dashboard for incident monitoring, triage prioritization, and detection trend analysis.

The workbook summarized Sentinel incidents across a focused 24-hour operational window and provided visibility into severity distribution, incident status, recent incidents, workload by severity/status, top incident titles, incident trends, and suspicious PowerShell activity.

The dashboard showed that the cyber range environment generated a large number of incidents, with most incidents remaining in a New state. The recent incident and workload panels helped identify which incidents required analyst attention, while the trend panels provided visibility into detection volume and suspicious activity over time.

The primary value of this lab was demonstrating the ability to turn raw Sentinel and Defender telemetry into an analyst-friendly SOC dashboard.

This project demonstrated the following skills:

    Microsoft Sentinel Workbooks
    KQL dashboard queries
    Incident reporting
    SOC workload visibility
    Triage prioritization
    Detection trend monitoring
    Security operations communication

---

### Recommended Improvements

- Add workbook parameters to let analysts switch between 24-hour, 3-day, and 7-day views
- Add severity and status filters for interactive triage
- Add owner-based filtering to identify unassigned incidents
- Add direct links from recent incidents to the Sentinel incident details page
- Add separate panels for identity-based incidents, endpoint incidents, and network-related incidents
- Add a watchlist for high-priority assets and surface incidents involving those systems
- Add workbook sections for closed incident trends and mean time to closure
- Add additional detection-specific panels for brute force, impossible travel, suspicious PowerShell, and network beaconing
- Use workbook parameters to allow SOC analysts to filter by incident title or detection rule
- Review recurring high-volume incident titles to identify detections that may require tuning
