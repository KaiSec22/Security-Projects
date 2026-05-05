## Active Directory Simulated Help Desk Environment — Domain Join to Account Recovery

### Environment & Scenario Context

This lab simulated a small enterprise Help Desk environment using **Windows Server 2022 (DC01)** as the domain controller and **Windows 10 (WIN10-A)** as the client workstation. The objective was to walk through practical support workflows commonly handled by Help Desk and IT support staff, including domain join operations, domain authentication validation, share permission troubleshooting, Group Policy enforcement, account lockout testing, and account recovery. 

The environment was built around the `corp.local` domain and was designed to mirror realistic administrative tasks performed in a Windows domain. The project focused on validating both functionality and traceability, ensuring that account actions and security events could be confirmed through native Windows administrative tools.

---

### Administrative Approach

Rather than approaching this project as a single configuration exercise, I treated it like a sequence of common Help Desk support tasks that might occur in a production environment.

The workflow focused on:

- Joining a workstation to the domain and verifying successful registration in Active Directory
- Confirming that domain user authentication worked as expected
- Testing role-based share access to validate permissions
- Applying a login banner through Group Policy to simulate enterprise compliance controls
- Configuring and testing an account lockout policy
- Recovering a locked-out user account and verifying the action through security logs

This approach helped demonstrate not just setup, but also validation, troubleshooting, and administrative follow-through.

---

### Administrative Tools Reviewed

- **Active Directory Users and Computers (ADUC)** — domain object management, account recovery
- **Group Policy Management** — login banner policy and account lockout enforcement
- **Windows Security Logs / Event Viewer** — verification of failed logons, account lockout, and password reset activity
- **Command Prompt** — domain user validation with `whoami`, policy verification with `net accounts`
- **NTFS and Share Permissions** — department-based access control testing

---

### Domain Join and Environment Setup

The first phase of the lab focused on joining the Windows 10 workstation to the `corp.local` domain. Before joining the machine, I verified connectivity to the domain controller, created a local administrator account, renamed the client to **WIN10-A**, and then completed the domain join.

After rebooting, I confirmed that the workstation appeared in Active Directory under the default **Computers** container, verifying that the domain join process completed successfully.

<img width="720" height="540" alt="image" src="https://github.com/user-attachments/assets/3a6f5b0d-2252-4c8d-92f5-b038ac5a7016" />

*Domain join confirmation screen*

**Findings:**

- The workstation successfully joined the `corp.local` domain
- The renamed client appeared in Active Directory as expected
- Network connectivity and domain communication were functioning correctly

---

### Domain User Logon Validation

After joining the workstation to the domain, I validated authentication by logging into **WIN10-A** as the domain user `corp\jdoe`. Once logged in, I opened Command Prompt and used `whoami` to confirm that the session was authenticated under the expected domain context.

This step verified that domain logons were functioning properly and that the workstation was correctly accepting domain credentials.

<img width="1015" height="812" alt="image" src="https://github.com/user-attachments/assets/15f29d16-b678-4122-aeb6-6d539751d2d2" />

*Command Prompt showing user identity as corp\jdoe*

**Findings:**

- Domain authentication succeeded on the client workstation
- The logged-in session reflected the expected domain identity
- The workstation was correctly integrated into the domain authentication workflow

---

### Department-Based File Share Access

To simulate common Help Desk permission validation tasks, I created three departmental shared folders on **DC01**:

- `IT_SHARE`
- `HR_SHARE`
- `FINANCE_SHARE`

I then applied appropriate NTFS and share permissions so that users could only access resources belonging to their assigned department. Testing from the workstation confirmed that:

- `jdoe` could access `IT_SHARE`
- `mchen` could access `FINANCE_SHARE`
- unauthorized access to `HR_SHARE` was denied when the user was not a member of the proper group

This phase demonstrated role-based access control and the practical validation of share permissions from the user side.

<img width="993" height="638" alt="image" src="https://github.com/user-attachments/assets/9e67e273-b7d2-4630-b4fb-7fba448c54f1" />
<img width="987" height="620" alt="image" src="https://github.com/user-attachments/assets/7ff357de-d93c-4844-9775-b574e41c2917" />

*IT employee successfully accessed `IT_SHARE` after share permissions were configured.*

<img width="1020" height="726" alt="image" src="https://github.com/user-attachments/assets/8d2b1fdb-e1c9-4820-824f-685d1329214a" />
<img width="1022" height="774" alt="image" src="https://github.com/user-attachments/assets/036d6142-f84a-4184-8ac9-a58d72996ff2" />

*Finance employee successfully accessed `FINANCE_SHARE` but was denied access to `HR_SHARE`, confirming department-based access controls were working as intended.*

**Findings:**

- Department-based share access worked as intended
- Authorized users could access their assigned folders
- Unauthorized users were denied access to restricted departmental shares
- Share and NTFS permissions aligned correctly with group membership

---

### Security Login Banner

To simulate a basic enterprise security control, I used **Group Policy Management** to configure a login banner for the workstation. The policy was set with the following values:

- **Message Title:** Authorized Access Only
- **Message Text:** This system is for authorized users only. Activity may be monitored.

After applying the policy and rebooting **WIN10-A**, the security banner appeared successfully prior to logon.

<img width="952" height="627" alt="image" src="https://github.com/user-attachments/assets/4ed50958-51eb-4ae9-a2bb-4ed0151a4404" />
<img width="1018" height="813" alt="image" src="https://github.com/user-attachments/assets/aa0e7e86-1ff3-46bb-adeb-7fd11eca8092" />

*Security login banner set through GP and displayed before login*

**Findings:**

- The login banner policy applied successfully through Group Policy
- The workstation displayed the configured message prior to authentication
- The environment demonstrated a common compliance-oriented endpoint control

---

### Account Lockout Policy Enforcement

Next, I created and linked a new Group Policy Object to enforce account lockout settings across the domain. The policy was configured with the following values:

- **Lockout threshold:** 4 invalid attempts
- **Lockout duration:** 30 minutes
- **Reset counter after:** 30 minutes

After forcing Group Policy to update, I confirmed the policy settings using `net accounts`, verifying that the lockout controls were in effect.

<img width="773" height="554" alt="image" src="https://github.com/user-attachments/assets/83f7ef82-a8d1-40a9-9104-0f98836de3f9" />
<img width="955" height="511" alt="image" src="https://github.com/user-attachments/assets/d6044d41-7de4-4c64-b0df-112db4562f00" />

*Account Lockout GPO creation and confirmation*

**Findings:**

- Account lockout settings were successfully applied through Group Policy
- The configured threshold and duration matched intended security controls
- The environment was prepared to detect and respond to repeated failed authentication attempts

---

### Lockout Simulation

To validate the lockout policy, I intentionally entered incorrect passwords multiple times for the HR user **Sarah Lee** (`corp\slee`). After the fourth failed attempt, the system displayed the expected lockout message:

> “The referenced account is currently locked out and may not be logged on to.”

This confirmed that the lockout policy was functioning as intended and that the domain controller was enforcing the configured threshold.

<img width="1017" height="816" alt="image" src="https://github.com/user-attachments/assets/9203930d-852f-4485-a912-791d212d8860" />

*4 failed password attempts lead to lockout*

**Findings:**

- The account lockout policy triggered as expected after repeated failed attempts
- The client displayed the expected lockout behavior
- The domain environment correctly enforced authentication protection settings

---

### Account Recovery and Security Event Verification

To simulate a standard Help Desk recovery workflow, I unlocked Sarah Lee’s account using **Active Directory Users and Computers**. After performing the recovery action, I opened **Event Viewer** on **DC01** and filtered the Security log to verify the audit trail associated with the incident.

The following event IDs were reviewed:

- **4625** — Failed logon attempts
- **4740** — Account lockout
- **4724** — Password reset

Finding these events confirmed that the lockout and recovery actions were both visible and traceable through native Windows logging.

<img width="406" height="535" alt="image" src="https://github.com/user-attachments/assets/dcb6462c-12db-4098-8392-8fa9f559eecf" />
<img width="846" height="702" alt="image" src="https://github.com/user-attachments/assets/a1fe89ae-f436-42cd-9bda-fa41cd2851db" />

*Unlocked the employees account and found the password reset in the event viewer to confirm traceability*

**Findings:**

- The locked account was successfully recovered through ADUC
- Security logs preserved a clear audit trail of the failed logons and lockout
- Password reset activity was verifiable through Event Viewer
- The recovery workflow demonstrated both administrative action and traceability

---

### Conclusion

This lab demonstrated a complete simulated Help Desk workflow inside a Windows domain environment. Starting with the domain join and ending with account recovery and event log verification, the project reflected the types of identity, permissions, and support tasks commonly handled in entry-level IT and Help Desk roles.

By validating domain logons, departmental share access, GPO enforcement, lockout behavior, and recovery actions, this lab showed both the operational and security side of Windows administration. It also reinforced the importance of auditability, since each major action could be traced through standard administrative tools and event logs.

Overall, the environment provided hands-on practice with realistic support scenarios while also producing a portfolio-ready demonstration of technical troubleshooting and systems administration.

---

### Recommended Improvements & Operational Takeaways

- Move client systems into dedicated OUs for cleaner Group Policy targeting
- Expand password policy and account lockout testing across multiple user roles
- Add shared printer deployment or mapped drive GPOs to simulate more Help Desk workflows
- Document common recovery procedures as repeatable support playbooks
- Continue building on event log analysis to strengthen both Help Desk and SOC troubleshooting skills
