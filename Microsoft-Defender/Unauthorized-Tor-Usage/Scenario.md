# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the Threat Actor took (Create Logs and IoCs):
1. Download the TOR browser installer from the official TOR Project website.
2. Install it silently using:
   ```cmd
   tor-browser-windows-x86_64-portable-15.0.8.exe /S
   ```
3. Open the TOR Browser from the installed folder on the desktop.
4. Connect to TOR and browse several sites to generate file, process, and network telemetry.
5. Create a text file on the desktop named `tor-shopping-list.txt` and add a few fake illicit items to simulate suspicious user activity.
6. Delete the file.

---

## Tables Used to Detect IoCs:
| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceFileEvents` |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| **Purpose** | Used to detect TOR installer download activity, TOR-related file creation on disk, and the creation of `tor-shopping-list.txt`. |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceProcessEvents` |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| **Purpose** | Used to detect silent execution of the TOR installer as well as the launch of `tor.exe` and `firefox.exe` from the TOR Browser directory. |

| **Parameter** | **Description** |
|---|---|
| **Name** | `DeviceNetworkEvents` |
| **Info** | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| **Purpose** | Used to detect TOR-related network activity, specifically connections initiated by `tor.exe` and `firefox.exe` over ports associated with TOR communications and browser usage. |

---

## Related Queries:
```kql
// Detect TOR-related file activity
DeviceFileEvents
| where DeviceName == "windows-vm-kwb"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256

// Detect silent TOR installer execution
DeviceProcessEvents
| where DeviceName == "windows-vm-kwb"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine

// Detect TOR Browser process execution
DeviceProcessEvents
| where DeviceName == "windows-vm-kwb"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
| order by Timestamp desc

// Detect TOR-related network connections
DeviceNetworkEvents
| where DeviceName == "windows-vm-kwb"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc

// Detect suspicious shopping list file creation
DeviceFileEvents
| where DeviceName == "windows-vm-kwb"
| where FileName contains "shopping-list.txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Kai Gallette
- **Author Contact**: https://github.com/KaiSec22
- **Date**: April 3, 2026