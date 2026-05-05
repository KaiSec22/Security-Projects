## Networking Troubleshooting Lab — Simulating Real Help Desk Internet Issues

### Environment & Scenario Context

This lab simulated one of the most common Help Desk tickets:

> “The user can’t connect to the internet.”

The environment used a Windows 10 client workstation named **WIN10-B**. The goal was to approach the issue like an IT Support Specialist by first documenting a healthy baseline, then intentionally breaking connectivity in realistic ways, testing the resulting symptoms, and restoring normal function.

The lab focused on practical troubleshooting scenarios involving:

- baseline connectivity validation
- physical adapter/network disconnection
- DNS failure
- incorrect IP and gateway configuration
- restoration and re-validation of connectivity

This project was built to reinforce networking fundamentals that directly apply to Help Desk and IT support work, especially around connectivity testing, DNS resolution, routing, and Windows network diagnostics. :contentReference[oaicite:1]{index=1}

---

### Troubleshooting Approach

Rather than treating “no internet” as a single problem, I broke the issue down into multiple failure domains and tested each one methodically.

The workflow focused on:

- confirming a known-good state before making changes
- identifying the difference between raw connectivity and name resolution
- observing the behavior of Windows when the adapter is disabled
- testing how incorrect static network settings affect routing
- restoring normal settings and validating recovery after each simulated issue

This reflects the same structured process used in real Help Desk environments, where users often report vague symptoms and the technician has to isolate the real cause. :contentReference[oaicite:2]{index=2}

---

### Administrative Tools Reviewed

- **Command Prompt** — `ipconfig`, `ping`, `nslookup`, `tracert`
- **Network and Sharing Center / Adapter Settings** — adapter disable and re-enable testing
- **IPv4 Adapter Properties** — DNS and static IP/gateway misconfiguration simulation

---

### Baseline Connectivity Validation

The first step was establishing a known-good network state before introducing failures. On **WIN10-B**, I opened Command Prompt as Administrator and ran the following commands:

```cmd
ipconfig
ping 8.8.8.8
ping google.com
nslookup google.com
tracert google.com
```

These tests confirmed that the workstation initially had working network connectivity, successful DNS name resolution, and a valid route to external internet resources.

<img width="681" height="723" alt="image" src="https://github.com/user-attachments/assets/b3fd5a90-fc45-4e35-bf6b-d4ab7f7d3bc4" />


**Findings:**

- The workstation had normal IP configuration
- Raw network connectivity was functional
- DNS resolved hostnames successfully
- Internet routing worked as expected

---

### Simulated Physical Network Disconnection

To simulate a real-world “user unplugged the cable” or disabled adapter scenario, I opened:

**Control Panel → Network and Sharing Center → Change Adapter Settings**

From there, I disabled the active network adapter. After disabling it, I attempted the following tests again:

```cmd
ping 8.8.8.8
ping google.com
ipconfig
```

The results showed a complete loss of connectivity, confirming that the machine no longer had any active network path. After documenting the failure state, I re-enabled the adapter and restored connectivity.

<img width="707" height="531" alt="image" src="https://github.com/user-attachments/assets/74fefc72-1b9f-4652-ba8a-5dad71037afd" />


**Findings:**

- Disabling the network adapter caused complete connectivity loss
- Both IP-based and hostname-based connectivity tests failed
- The issue behaved like a physical disconnection or unplugged cable
- Re-enabling the adapter restored normal connectivity

---

### DNS Failure Simulation

Next, I simulated a DNS issue to demonstrate a scenario where “the internet works, but websites do not load.” To do this, I manually changed the DNS server setting to:

```text
127.0.0.1
```

Then I tested:

```cmd
ping 8.8.8.8
ping google.com
nslookup google.com
```

This created the expected split behavior:

- `ping 8.8.8.8` still worked
- `ping google.com` failed
- `nslookup google.com` failed

This proved that network connectivity was still present, but DNS name resolution was broken. After testing, I restored the correct DNS settings and confirmed that name resolution worked again. :contentReference[oaicite:3]{index=3}

<img width="394" height="449" alt="image" src="https://github.com/user-attachments/assets/84f106a3-1ed7-4b1f-8758-52d8a586c049" />

<img width="723" height="457" alt="image" src="https://github.com/user-attachments/assets/92eeca98-3ecf-4ab2-90e0-9b8ce18b4dd7" />


*Setting DNS to `127.0.0.1` preserved raw connectivity while breaking hostname resolution, accurately simulating a common Help Desk DNS issue.*

**Findings:**

- The system still had internet reachability by IP
- DNS resolution failed for hostnames
- Websites and named resources could not be reached without working DNS
- Restoring correct DNS settings returned the system to normal operation

---

### Wrong Gateway / Routing Failure Simulation

To simulate bad IP configuration or a user placed on the wrong network, I manually assigned the following settings:

- **IP Address:** `192.168.1.55`
- **Subnet Mask:** `255.255.255.0`
- **Default Gateway:** `192.168.1.1`
- **DNS Server:** `8.8.8.8`

Although the settings appeared valid at a glance, they placed the workstation on the wrong network path and removed its ability to route traffic correctly.

I then tested:

```cmd
ping 8.8.8.8
tracert google.com
```

The system failed to reach the internet, and routing failed immediately. This simulated the kind of issue caused by incorrect static addressing, wrong gateway assignments, or users connected to the wrong network segment. After completing the test, I restored automatic IP and DNS configuration and verified that connectivity returned. :contentReference[oaicite:4]{index=4}

<img width="640" height="479" alt="image" src="https://github.com/user-attachments/assets/a84eee13-51e5-4fb6-b5f7-dd8051339f70" />

<img width="720" height="418" alt="image" src="https://github.com/user-attachments/assets/41f33128-5365-457d-ba4d-8e81a8b86d5e" />


*Incorrect static addressing and gateway configuration removed the host’s valid path to the internet, demonstrating a routing failure scenario common in real support environments.*

**Findings:**

- The workstation lost internet access due to incorrect network configuration
- Routing failed even though the settings initially looked reasonable
- The issue simulated a wrong subnet or wrong gateway scenario
- Returning the adapter to automatic settings restored connectivity

---

### Restoration and Recovery Validation

After each simulated issue, I restored the workstation to a known-good state and re-ran connectivity checks to confirm successful recovery.

Typical validation steps included:

```cmd
ipconfig
ping 8.8.8.8
ping google.com
nslookup google.com
tracert google.com
```

This final recovery phase confirmed that each issue had been resolved correctly and that the workstation had returned to normal operation.


**Findings:**

- Normal network function was restored after each test
- Connectivity, DNS, and routing were successfully re-validated
- The troubleshooting process confirmed both the cause of failure and the effectiveness of recovery actions

---

### Conclusion

This lab demonstrated a realistic Help Desk-style networking troubleshooting workflow using a Windows 10 client workstation. By first validating a healthy baseline and then simulating multiple failure scenarios, I was able to observe how Windows behaves during different types of internet-related issues and confirm the correct troubleshooting path for each one.

The lab showed the difference between:

- complete network disconnection
- DNS-specific failure
- incorrect routing caused by bad gateway configuration

It also reinforced the importance of structured troubleshooting rather than guessing. Each issue was isolated, tested, documented, and resolved using standard Windows tools that are commonly used in Help Desk and IT support roles. This made the project both technically useful and directly relevant to real-world support work. :contentReference[oaicite:5]{index=5}

---

### Recommended Improvements & Operational Takeaways

- Always establish a known-good baseline before troubleshooting user issues
- Separate IP connectivity testing from hostname resolution testing
- Use `ping`, `nslookup`, and `tracert` together to isolate the real source of network problems
- Remember that “internet is down” may actually be a DNS or routing issue
- Continue building repeatable troubleshooting playbooks for common Help Desk tickets such as no internet, slow browsing, DNS failure, and bad IP configuration
