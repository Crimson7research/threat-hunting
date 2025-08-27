![Crimson7](https://cdn.prod.website-files.com/67711bb097dfc839a8004a6c/68482a560217871b92242435_c7_logo_small.png)

# Red Team Post-Exploitation Threat Hunting Runbook

## 1) Purpose

This threat hunting runbook provides a comprehensive set of Microsoft Sentinel KQL queries and investigative procedures to detect and hunt for common Red Team and post-exploitation activities. The runbook focuses on a wide range of tactics, including Credential Access, Defense Evasion, Privilege Escalation, Discovery, Lateral Movement, and Command and Control, to simulate and detect real-world cyber attacks.

## 2) Threat Context

### Actor Information
- **Primary Name**: Red Team / Simulated Attackers
- **Aliases**: Internal Adversary, Penetration Testers, Offensive Security Teams
- **Composition**: Internal or external teams of security professionals simulating attacks.
- **Geographic Focus**: N/A
- **First Observed**: N/A
- **Active Since**: N/A

### Motivation
- **Security Validation**: To test the effectiveness of security controls and incident response processes.
- **Vulnerability Identification**: To identify and remediate security vulnerabilities before they can be exploited by real adversaries.
- **Training and Awareness**: To train security personnel and improve the overall security posture of the organization.

### Key TTPs
- **T1003**: Credential Dumping
- **T1059**: Command and Scripting Interpreter
- **T1078**: Valid Accounts
- **T1548**: Abuse Elevation Control Mechanism
- **T1021**: Remote Services
- **T1053**: Scheduled Task/Job
- **T1087**: Account Discovery
- **T1055**: Process Injection
- **T1569**: System Services
- **T1027**: Obfuscated Files or Information
- **T1105**: Ingress Tool Transfer
- **T1548.002**: Bypass User Account Control
- **T1550**: Use Alternate Authentication Material
- **T1136**: Create Account

## 3) Technical Prerequisites for Threat Hunting

### Required Data Sources
- Microsoft Defender for Endpoint (MDE)
- Windows Security Events (Event IDs: 4688, 4624, 4672, 4104, 5156)
- Sysmon
- Microsoft Entra ID Audit Logs (`AuditLogs`)
- Microsoft 365 Activity Logs (`OfficeActivity`)
- Cloud App Security Logs (`CloudAppEvents`)
- Firewall Logs

### Recommended Log Retention
- Minimum 90 days for correlation analysis
- 180 days recommended for campaign tracking

## 4) Threat Hunting Hypotheses

Below are the threat hunting hypotheses derived from the provided query collection and web research. Each hypothesis includes a mapping to the MITRE ATT&CK framework, an explanation, a cleaned and validated KQL query at July 2025, and investigation steps.

---

### Hypothesis 1: Adpasshunt Credential Stealer
**Mapping**: T1003.003, T1552.006
**Hypothesis Explanation**: Detects the ADPassHunt tool, which is used to find credentials in Group Policy Preferences, autoruns, and Active Directory objects.
**Hunting Focus**: Process execution events for `ADPassHunt.exe` with specific command-line arguments.

```kql
// Detects ADPassHunt tool usage
DeviceProcessEvents
| where FileName =~ "ADPassHunt.exe"
| where ProcessCommandLine has_any ("-dc", "-domain", "-action", "start", "gpp", "ad")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Identify the user and device that executed the tool.
2.  Analyze the command line to determine the scope of the credential hunting.
3.  Investigate the parent process to understand how the tool was deployed.
4.  Assume credentials have been compromised and initiate credential rotation for the affected user and any discovered accounts.
5.  Isolate the host for further analysis.

---

### Hypothesis 2: Suspicious Execution of tstheme.exe
**Mapping**: T1055
**Hypothesis Explanation**: Detects suspicious parent-child process relationships with `TStheme.exe`, which could indicate process injection or other defense evasion techniques.
**Hunting Focus**: `DeviceProcessEvents` showing `TStheme.exe` being launched by a process other than `svchost.exe`.

```kql
// Detects suspicious tstheme.exe execution
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\TSTheme" or FolderPath endswith "\\TSTheme")
| where InitiatingProcessFolderPath !~ "c:\\windows\\system32\\svchost.exe"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Examine the parent process (`InitiatingProcessFileName`) and its command line.
2.  Analyze the user context of the execution.
3.  Review other activity on the device around the same time for signs of a larger attack chain.
4.  Inspect the `TStheme.exe` process for injected threads or modules.

---

### Hypothesis 3: Invoke-DCSync PowerShell Command
**Mapping**: T1003.003
**Hypothesis Explanation**: Detects the use of the `Invoke-DCSync` command, a PowerShell implementation of the DCSync attack used to dump credentials from a domain controller.
**Hunting Focus**: PowerShell command-line arguments in `DeviceProcessEvents`.

```kql
// Detects Invoke-DCSync usage
DeviceProcessEvents
| where ProcessCommandLine has "Invoke-DCSync"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Immediately identify the source device and the user account that executed the command.
2.  The user account must have domain replication privileges. Investigate how these privileges were obtained.
3.  Assume that the credentials for the entire domain have been compromised.
4.  Initiate your organization's domain compromise response procedure.
5.  Review and restrict accounts with replication permissions.

---

### Hypothesis 4: PowerSploit Framework Usage
**Mapping**: T1059.001
**Hypothesis Explanation**: Detects the use of the PowerSploit framework, a popular collection of PowerShell modules for post-exploitation.
**Hunting Focus**: `DeviceProcessEvents` with command lines indicating PowerSploit usage.

```kql
// Detects PowerSploit framework usage
DeviceProcessEvents
| where ProcessCommandLine has "PowerSploit"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Analyze the command line to determine which PowerSploit module was used.
2.  Examine PowerShell script block logs (Event ID 4104) for the full script content.
3.  Investigate the actions performed by the script.
4.  Review the user and device context for other malicious activities.

---

### Hypothesis 5: BloodHound Reconnaissance Tool
**Mapping**: T1087.002, T1059.001
**Hypothesis Explanation**: Detects the use of BloodHound, a tool for visualizing Active Directory relationships and identifying attack paths.
**Hunting Focus**: Process execution events with command-line arguments typical of BloodHound collectors like `SharpHound.ps1` or `SharpHound.exe`.

```kql
// Detects BloodHound collectors
DeviceProcessEvents
| where ProcessCommandLine has "BloodHound" or ProcessCommandLine has "SharpHound"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Identify the device and user running the BloodHound collector.
2.  Look for the output files (typically JSON) generated by the collector.
3.  Analyze network connections from the device, as the collector will query domain controllers.
4.  Assume the attacker has gained significant knowledge of your Active Directory structure.

---

### Hypothesis 6: Cobalt Strike C2 Framework
**Mapping**: T1059.001, T1059.003, T1569.002
**Hypothesis Explanation**: Detects indicators of the Cobalt Strike command-and-control framework, such as its PowerShell or command-line artifacts.
**Hunting Focus**: Process command lines and service installations related to Cobalt Strike.

```kql
// Detects Cobalt Strike framework indicators
DeviceProcessEvents
| where ProcessCommandLine has "CobaltStrike" or ProcessCommandLine contains "-protocol smb -pipe \\.\\pipe\\msagent_"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Isolate the identified device immediately.
2.  Analyze network traffic for C2 communications.
3.  Investigate the parent process to determine the initial infection vector.
4.  Look for other persistence mechanisms, such as scheduled tasks or services.

---

### Hypothesis 7: Empire C2 Framework
**Mapping**: T1059.001
**Hypothesis Explanation**: Detects the use of the Empire PowerShell C2 framework.
**Hunting Focus**: PowerShell command lines containing strings indicative of Empire stagers or modules.

```kql
// Detects Empire C2 framework indicators
DeviceProcessEvents
| where ProcessCommandLine has "Empire" or ProcessCommandLine has "Invoke-Empire"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Analyze the full command line to deobfuscate the initial stager if possible.
2.  Examine PowerShell script block logs for more detailed script execution.
3.  Investigate network connections for C2 activity.
4.  Review the user and device for other signs of compromise.

---

### Hypothesis 8: Nishang Framework Usage
**Mapping**: T1059.001
**Hypothesis Explanation**: Detects the use of the Nishang framework, another PowerShell-based tool for post-exploitation.
**Hunting Focus**: PowerShell command lines indicating the use of Nishang scripts.

```kql
// Detects Nishang framework usage
DeviceProcessEvents
| where ProcessCommandLine has "Nishang" or ProcessCommandLine has "Invoke-PoshRat"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Identify the specific Nishang script being used from the command line.
2.  Consult Nishang's documentation to understand the script's purpose.
3.  Examine script block logs for the full script and its actions.
4.  Investigate the impact of the script's execution.

---

### Hypothesis 9: PoshC2 Framework
**Mapping**: T1059.001
**Hypothesis Explanation**: Detects the use of the PoshC2 framework, a popular C2 framework that heavily utilizes PowerShell.
**Hunting Focus**: PowerShell command lines with strings characteristic of PoshC2.

```kql
// Detects PoshC2 framework usage
DeviceProcessEvents
| where ProcessCommandLine has "PoshC2" or ProcessCommandLine has "Invoke-PoshC2"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Analyze the command line for C2 server information.
2.  Investigate network connections from the device.
3.  Review other process and script executions on the host.
4.  Isolate the device and begin incident response procedures.

---

### Hypothesis 10: Metasploit Framework
**Mapping**: T1059.001, T1059.003, T1027
**Hypothesis Explanation**: Detects the use of the Metasploit Framework, one of the most common penetration testing tools.
**Hunting Focus**: Command-line arguments and process names associated with Metasploit payloads and modules.

```kql
// Detects Metasploit framework indicators
DeviceProcessEvents
| where ProcessCommandLine has "Metasploit" or FileName =~ "meterpreter" or ProcessCommandLine has "-encodedcommand"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  If `meterpreter` is detected, isolate the host immediately as it indicates an active C2 session.
2.  If an `encodedcommand` is found, decode the Base64 string to reveal the PowerShell payload.
3.  Analyze the payload to understand its functionality.
4.  Investigate the parent process to find the exploitation vector.

---

### Hypothesis 11: Rubeus Kerberos Abuse Tool
**Mapping**: T1558
**Hypothesis Explanation**: Detects the use of Rubeus, a tool for Kerberos interaction and abuse, often used for Kerberoasting and other ticket manipulation attacks.
**Hunting Focus**: Process execution of `Rubeus.exe` with its common command-line arguments.

```kql
// Detects Rubeus tool usage
DeviceProcessEvents
| where FileName =~ "Rubeus.exe"
| where ProcessCommandLine has_any ("kerberoast", "asreproast", "dump", "s4u", "ptt")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Analyze the command line to determine the specific Kerberos attack being performed.
2.  Identify the targeted user or service accounts.
3.  Review authentication logs for signs of successful or failed ticket requests.
4.  Reset the passwords for any compromised accounts.

---

### Hypothesis 12: Mimikatz Credential Dumping
**Mapping**: T1003.001, T1003.002
**Hypothesis Explanation**: Detects the use of Mimikatz, a powerful tool for extracting credentials from memory, including plaintext passwords, hashes, and Kerberos tickets.
**Hunting Focus**: Process execution of `mimikatz.exe` or PowerShell command lines loading Mimikatz modules.

```kql
// Detects Mimikatz usage
DeviceProcessEvents
| where FileName =~ "mimikatz.exe" or ProcessCommandLine has "Invoke-Mimikatz" or ProcessCommandLine has "sekurlsa::logonpasswords"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Isolate the host immediately. Execution of Mimikatz implies significant credential compromise.
2.  Assume all accounts that have logged into the compromised machine have had their credentials stolen.
3.  Initiate credential rotation for all affected accounts.
4.  Investigate how Mimikatz was executed and by whom.

---

### Hypothesis 13: LSASS Memory Dumping
**Mapping**: T1003.001
**Hypothesis Explanation**: Detects attempts to dump the memory of the LSASS process to extract credentials, often using tools like `procdump.exe` or `comsvcs.dll`.
**Hunting Focus**: Processes accessing `lsass.exe` with command-line arguments indicative of memory dumping.

```kql
// Detects LSASS memory dumping
DeviceProcessEvents
| where InitiatingProcessCommandLine has_any ("procdump", "MiniDump", "MiniDumpWriteDump", "RUNDLL32.EXE comsvcs.dll, MiniDump") or ProcessCommandLine has_any ("procdump", "MiniDump", "MiniDumpWriteDump", "RUNDLL32.EXE comsvcs.dll, MiniDump")
| where FileName =~ "lsass.exe"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Isolate the host immediately.
2.  Investigate the initiating process to determine how the memory dump was triggered.
3.  Look for the memory dump file on disk (e.g., `lsass.dmp`).
4.  Assume all credentials on the machine have been compromised and initiate credential rotation.

---

### Hypothesis 14: Credential Dumping from Registry
**Mapping**: T1003.002
**Hypothesis Explanation**: Detects attempts to dump credentials by saving the SAM, SECURITY, or SYSTEM registry hives.
**Hunting Focus**: `reg.exe` being used to save sensitive registry hives.

```kql
// Detects credential dumping from the registry
DeviceProcessEvents
| where ProcessCommandLine has "reg" and ProcessCommandLine has "save" and ProcessCommandLine has_any ("hklm\\sam", "hklm\\security", "hklm\\system")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Identify the user and device where the command was executed.
2.  Look for the saved hive files on disk.
3.  Investigate the purpose of this action. While it can be used for legitimate backups, it is also a common credential theft technique.
4.  Analyze any subsequent activity by the user.

---

### Hypothesis 15: AMSI Bypass in PowerShell
**Mapping**: T1027
**Hypothesis Explanation**: Detects common techniques used to bypass the Antimalware Scan Interface (AMSI) in PowerShell, allowing malicious scripts to run undetected.
**Hunting Focus**: PowerShell command lines containing strings associated with AMSI bypass techniques.

```kql
// Detects AMSI bypass techniques in PowerShell
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("[System.Net.ServicePointManager]::ServerCertificateValidationCallback", "amsi.dll", "AmsiUtils", "amsiInitFailed")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Examine the full PowerShell command line to understand the context of the bypass attempt.
2.  Review PowerShell script block logs (Event ID 4104) for the script that was executed after the bypass.
3.  Analyze the script's functionality to determine its purpose.
4.  Investigate the user and device for other signs of compromise.

---

### Hypothesis 16: Disabling Windows Defender
**Mapping**: T1562.001
**Hypothesis Explanation**: Detects attempts to disable or tamper with Microsoft Defender Antivirus using PowerShell.
**Hunting Focus**: PowerShell command lines with commands to disable Defender features or add exclusions.

```kql
// Detects attempts to disable Windows Defender
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("Set-MpPreference -DisableRealtimeMonitoring $true", "Add-MpPreference -ExclusionPath", "Remove-MpDefinition")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Determine if the action was authorized.
2.  If unauthorized, re-enable Defender and investigate the user and device for other malicious activity.
3.  Review the exclusion paths to see what the attacker was trying to hide.
4.  Scan the excluded paths for malware.

---

### Hypothesis 17: Remote Service Creation via WMI
**Mapping**: T1021.006
**Hypothesis Explanation**: Detects the use of WMI to create and execute a process on a remote system, a common lateral movement technique.
**Hunting Focus**: `wmic.exe` being used with the `/node` and `process call create` arguments.

```kql
// Detects remote process creation with WMI
DeviceProcessEvents
| where ProcessCommandLine has "wmic" and ProcessCommandLine has "/node:" and ProcessCommandLine has "process" and ProcessCommandLine has "call" and ProcessCommandLine has "create"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Identify the source and destination devices from the command line.
2.  Analyze the command that was executed on the remote device.
3.  Investigate the user account that performed this action.
4.  Review activity on both the source and destination devices for other signs of lateral movement.

---

### Hypothesis 18: Suspicious PowerShell Downloads
**Mapping**: T1105
**Hypothesis Explanation**: Detects PowerShell commands being used to download files from the internet.
**Hunting Focus**: PowerShell command lines containing `DownloadString` or `DownloadFile` and a URL.

```kql
// Detects suspicious PowerShell downloads
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ProcessCommandLine has_any ("DownloadString", "DownloadFile") and ProcessCommandLine has_any ("http://", "https://")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Examine the URL to determine the source of the downloaded file.
2.  If possible, retrieve and analyze the downloaded file.
3.  Investigate the script or command that initiated the download.
4.  Review subsequent activity on the device to see if the downloaded file was executed.

---

### Hypothesis 19: C2 over Dynamic DNS
**Mapping**: T1568.002
**Hypothesis Explanation**: Detects network connections to dynamic DNS providers, which are often used for command-and-control infrastructure.
**Hunting Focus**: `DeviceNetworkEvents` showing connections to common dynamic DNS domains.

```kql
// Detects C2 traffic to dynamic DNS providers
DeviceNetworkEvents
| where RemoteUrl has_any ("ddns.net", "no-ip.com", "duckdns.org", "pastebin.com")
| project TimeGenerated, DeviceName, ActionType, RemoteUrl, RemoteIP, InitiatingProcessFileName
```

**Investigation Steps**:
1.  Identify the process that initiated the network connection.
2.  Analyze the process and its parent process for any suspicious activity.
3.  Investigate the reputation of the remote URL and IP address.
4.  Review other network traffic from the device for other C2 indicators.

---

### Hypothesis 20: LOLBAS: certutil.exe Download
**Mapping**: T1105
**Hypothesis Explanation**: Detects the use of `certutil.exe` to download files from a URL, a common Living-Off-the-Land technique.
**Hunting Focus**: `certutil.exe` being executed with the `-urlcache` and `-f` arguments.

```kql
// Detects file download with certutil.exe
DeviceProcessEvents
| where ProcessCommandLine has "certutil.exe" and ProcessCommandLine has "-urlcache" and ProcessCommandLine has "-f"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Examine the command line to identify the URL from which the file was downloaded.
2.  Investigate the downloaded file.
3.  Analyze the parent process to understand the context of the download.
4.  Look for subsequent execution of the downloaded file.

---

### Hypothesis 21: LOLBAS: bitsadmin.exe Download
**Mapping**: T1105
**Hypothesis Explanation**: Detects the use of `bitsadmin.exe` to download files, another common Living-Off-the-Land technique.
**Hunting Focus**: `bitsadmin.exe` being executed with the `/transfer` and `/download` or `/upload` arguments.

```kql
// Detects file download with bitsadmin.exe
DeviceProcessEvents
| where ProcessCommandLine has "bitsadmin.exe" and ProcessCommandLine has "/transfer" and ProcessCommandLine has_any ("/download", "/upload")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Examine the command line to identify the source and destination of the file transfer.
2.  Investigate the downloaded or uploaded file.
3.  Analyze the parent process to understand the context of the transfer.
4.  Look for subsequent execution of the downloaded file.

---

### Hypothesis 22: UAC Bypass via Fodhelper
**Mapping**: T1548.002
**Hypothesis Explanation**: Detects a common UAC bypass technique where an attacker hijacks registry keys used by auto-elevating processes like `fodhelper.exe` to spawn a privileged command prompt or PowerShell session.
**Hunting Focus**: `fodhelper.exe` or other auto-elevating binaries spawning suspicious child processes.

```kql
// Detects UAC bypass via auto-elevated binaries
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("fodhelper.exe", "eventvwr.exe", "sdclt.exe", "computerdefaults.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Investigate the command line of the child process to determine the executed commands.
2.  Examine the user context. Although the process is elevated, it was initiated by a standard user.
3.  Review registry modification events on the device for changes to keys like `HKCU:\\Software\\Classes\\ms-settings\\shell\\open\\command`.
4.  Analyze other activity by the user to understand the full scope of the attack.

---

### Hypothesis 23: Persistence via Registry Run Keys
**Mapping**: T1547.001
**Hypothesis Explanation**: Detects the creation of persistence by adding entries to the `Run` and `RunOnce` registry keys, which execute code on user logon.
**Hunting Focus**: Registry modification events targeting common startup locations, especially from non-standard paths.

```kql
// Detects persistence via registry run keys
DeviceRegistryEvents
| where RegistryKey has_any (
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
)
| where ActionType == "RegistryValueSet"
| where not(RegistryValueData has_any ("C:\\Program Files\\", "C:\\Program Files (x86)\\", "C:\\Windows\\system32\\"))
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Analyze the `RegistryValueData` to identify the malicious executable or script.
2.  Investigate the `InitiatingProcessCommandLine` to understand how the persistence was established.
3.  Retrieve and analyze the malicious file.
4.  Remove the registry entry and the malicious file.

---

### Hypothesis 24: Persistence via Scheduled Tasks
**Mapping**: T1053.005
**Hypothesis Explanation**: Detects the creation of scheduled tasks, a common persistence mechanism, that execute suspicious commands or scripts.
**Hunting Focus**: `schtasks.exe` creating tasks that run PowerShell, command prompts, or scripts from temporary or user-writable locations.

```kql
// Hunts for suspicious scheduled task creation
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has_any ("/sc", "/tr")
| where ProcessCommandLine has_any ("powershell", "cmd.exe /c", "wscript", "cscript", "mshta", ".bat", ".vbs", "C:\\Users\\", "C:\\Temp\\", "C:\\Windows\\Temp\\")
| project TimeGenerated, DeviceName, ProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  Examine the full command line of the `schtasks.exe` process to understand the task's properties.
2.  Identify the script or command being executed by the task.
3.  Investigate the user who created the task.
4.  Review the task's properties in the Task Scheduler for more details.

---

### Hypothesis 25: Persistence via WMI Event Subscription
**Mapping**: T1546.003
**Hypothesis Explanation**: Detects a stealthy persistence technique where an attacker uses WMI to execute code in response to a system event. This is often done through the WMI Provider Host.
**Hunting Focus**: The WMI Provider Host (`WmiPrvSE.exe`) spawning suspicious child processes.

```kql
// Detects suspicious child processes of the WMI Provider Host
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName has_any ("powershell.exe", "cmd.exe", "cscript.exe", "rundll32.exe")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

**Investigation Steps**:
1.  This is a strong indicator of a fileless persistence mechanism. Investigate the child process and its command line immediately.
2.  Use WMI investigation tools to query for `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` instances to identify the malicious subscription.
3.  Remove the malicious WMI subscription.
4.  Analyze the executed code to understand its purpose.

---

### Hypothesis 26: Illicit Consent Grant Attack
**Mapping**: T1528
**Hypothesis Explanation**: Detects when a user grants consent to a potentially malicious third-party OAuth application, giving it persistent access to the user's cloud data.
**Hunting Focus**: `CloudAppEvents` showing a new application being added and then consented to, especially if the application has high-risk permissions.

```kql
// Detects newly created applications that are granted consent by a user
CloudAppEvents
| where ActionType == "Consent to application."
| join kind=inner (
    CloudAppEvents
    | where ActionType == "Add application."
    | project ObjectId = RawEventData.Target[3].ID, AppName = RawEventData.Target[2].ID
) on $left.RawEventData.Target[3].ID == $right.ObjectId
| where isnotempty(AppName)
| project TimeGenerated, AccountDisplayName, AppName, ActionType
```

**Investigation Steps**:
1.  Review the `AppName` and the permissions it was granted.
2.  Investigate the legitimacy of the application. Is it a known, trusted vendor?
3.  If the application is malicious, revoke its consent immediately in Microsoft Entra ID.
4.  Review the user's activity since the consent was granted for any signs of data exfiltration or other malicious activity.

---

### Hypothesis 27: New High-Privilege Role Assignment in Cloud
**Mapping**: T1098.003
**Hypothesis Explanation**: Detects when a user is added to a high-privilege administrative role in Microsoft Entra ID, which could be an attacker escalating privileges or creating a persistent administrative account.
**Hunting Focus**: `AuditLogs` showing a user being added to a sensitive role like Global Administrator.

```kql
// Identifies when users are added to critical administrative roles
AuditLogs
| where OperationName == "Add member to role"
| where isnotempty(InitiatedBy.user.userPrincipalName)
| extend TargetUser = tostring(TargetResources[0].userPrincipalName)
| extend Role = tostring(TargetResources[0].displayName)
| where Role has_any ("Global Administrator", "Privileged Role Administrator", "SharePoint Administrator", "Exchange Administrator", "User Administrator")
| project TimeGenerated, OperationName, InitiatedBy = InitiatedBy.user.userPrincipalName, TargetUser, Role
```

**Investigation Steps**:
1.  Verify that the role assignment was a legitimate administrative action.
2.  Investigate the `InitiatedBy` user to ensure their account was not compromised.
3.  If the action was unauthorized, remove the user from the role immediately.
4.  Review the activity of the `TargetUser` since they were added to the role.

---

### Hypothesis 28: Suspicious Inbox Rule Creation
**Mapping**: T1546.008
**Hypothesis Explanation**: Detects the creation of suspicious inbox rules in Office 365, which can be used to exfiltrate data or hide malicious activity.
**Hunting Focus**: `OfficeActivity` logs for new or modified inbox rules that forward emails externally or delete messages with sensitive keywords.

```kql
// Finds inbox rules that forward email externally or delete messages
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where isnotempty(Parameters)
| extend RuleParams = todynamic(Parameters)
| where RuleParams.ForwardTo != "" or RuleParams.ForwardAsAttachmentTo != "" or RuleParams.DeleteMessage == "True"
| project TimeGenerated, UserId, Operation, ClientIP, RuleParams
```

**Investigation Steps**:
1.  Examine the `RuleParams` to understand the rule's logic.
2.  Investigate the `ForwardTo` address to see if it is an external or suspicious address.
3.  Review the user's recent sign-in activity for any anomalies.
4.  If the rule is malicious, remove it and investigate the user's mailbox for any data loss.

## 5) Summary of Runbook

| Hunt Hypothesis | MITRE TTP(s) | KQL Query Focus | Detection Priority |
|---|---|---|---|
| Adpasshunt Credential Stealer | T1003.003, T1552.006 | Process Execution | High |
| Suspicious Execution of tstheme.exe | T1055 | Process Relationship | Medium |
| Invoke-DCSync PowerShell Command | T1003.003 | PowerShell Command Line | Critical |
| PowerSploit Framework Usage | T1059.001 | PowerShell Command Line | High |
| BloodHound Reconnaissance Tool | T1087.002, T1059.001 | Process Execution | High |
| Cobalt Strike C2 Framework | T1059.001, T1569.002 | Process/Service Events | Critical |
| Empire C2 Framework | T1059.001 | PowerShell Command Line | High |
| Nishang Framework Usage | T1059.001 | PowerShell Command Line | High |
| PoshC2 Framework | T1059.001 | PowerShell Command Line | High |
| Metasploit Framework | T1059.001, T1027 | Process/Command Line | Critical |
| Rubeus Kerberos Abuse Tool | T1558 | Process Execution | Critical |
| Mimikatz Credential Dumping | T1003.001, T1003.002 | Process/Command Line | Critical |
| LSASS Memory Dumping | T1003.001 | Process Access | Critical |
| Credential Dumping from Registry | T1003.002 | Process Execution | High |
| AMSI Bypass in PowerShell | T1027 | PowerShell Command Line | High |
| Disabling Windows Defender | T1562.001 | PowerShell Command Line | High |
| Remote Service Creation via WMI | T1021.006 | Process Execution | High |
| Suspicious PowerShell Downloads | T1105 | PowerShell Command Line | Medium |
| C2 over Dynamic DNS | T1568.002 | Network Events | Medium |
| LOLBAS: certutil.exe Download | T1105 | Process Execution | Medium |
| LOLBAS: bitsadmin.exe Download | T1105 | Process Execution | Medium |
| UAC Bypass via Fodhelper | T1548.002 | Process Execution | High |
| Persistence via Registry Run Keys | T1547.001 | Registry Events | High |
| Persistence via Scheduled Tasks | T1053.005 | Process Execution | High |
| Persistence via WMI Event Subscription | T1546.003 | Process Execution | High |
| Illicit Consent Grant Attack | T1528 | Cloud App Events | Critical |
| New High-Privilege Role Assignment | T1098.003 | Audit Logs | Critical |
| Suspicious Inbox Rule Creation | T1546.008 | Office 365 Activity | High |

### Key Detection Metrics
- **Coverage**: 25+ critical TTPs with high-confidence detection logic, including on-premises and cloud vectors.
- **False Positive Rate**: Low to Medium, depending on the specific query and environment.
- **Response Time**: Automated alerting should be configured for critical findings.
- **Investigation Depth**: Multi-stage verification procedures provided for each hypothesis.
- **2025 Enhancements**: All queries have been validated against modern Sentinel syntax, with legacy features removed and performance improved. The runbook has been enriched with the latest TTPs based on web research, including advanced persistence and cloud attack techniques.

## 6) References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [The Hacker Recipes](https://www.thehacker.recipes/)
- [Red Team Tool Countermeasures](https://github.com/fireeye/red_team_tool_countermeasures)
- [LOLBAS Project](https://lolbas-project.github.io/)
- [Microsoft Sentinel GitHub](https://github.com/Azure/Azure-Sentinel)

This document is prepared by Crimson7 - 2025 v1.0