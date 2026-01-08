### Sentinel-Automation Near Real Time Rule

This Sentinel near–real-time automation rule is designed to detect brute-force authentication activity followed by a successful login within a defined time window. The rule identifies multiple failed authentication attempts against the same account and correlates them with a subsequent successful sign-in, a pattern commonly associated with credential guessing, password spraying, or compromised credentials.

By leveraging endpoint and identity telemetry, this detection enables rapid identification of high risk authentication events, allowing security teams to respond quickly with automated actions such as  raising an alert, changing incident severity, and assigning the incident to an analyst. This approach helps reduce an attacker's time spent on the system and strengthens an organisation’s ability to detect and respond to account compromise attempts in near real time.

#### What Is a Near Real-Time (NRT) Rule?

A Near Real-Time (NRT) rule is a type of detection rule in Microsoft Sentinel that continuously evaluates incoming security data as it is ingested, allowing alerts to be generated within seconds to a few minutes of an event occurring.

Unlike scheduled analytics rules that run at fixed intervals (for example, every 5 or 15 minutes), NRT rules operate on a streaming model, enabling faster detection of active threats such as brute-force attacks, account compromise, or lateral movement.

NRT rules are ideal when:
  - Immediate response is critical (e.g., credential compromise).
  - Trigger automation playbooks quickly.
  - The detection logic is well-defined and low-noise.
  - The need for rapid visibility into attacker behavior.


#### NRT Rule Configuration

On the Azure portal, navigate to Microsoft Sentinel > Log Analytics workbook > Analytics, then select Create  > NRT query rule

Fill in the query name, associated MITRE ATT&CK category 

![image alt](https://github.com/Muts256/SNC-Public/blob/08f729e67089f862f952eb191b522cec05abe3bc/Images/Sentinel-Automation/Sr1.png)

On the set rule logic page, create the query that will be used to detect the failed logins

```
let failedThreshold = 10;
let lookbackTime = 1h;
let successWindow = 3m;
DeviceLogonEvents
| where DeviceName contains "MM-atomicred-vm"
| where TimeGenerated > ago(lookbackTime)
| where ActionType == "LogonFailed"
| summarize
    FailedCount = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated),
    FailureIPs = make_set(RemoteIP, 10),
    LogonTypes = make_set(LogonType, 5)
    by AccountName, DeviceName
| where FailedCount >= failedThreshold
| join kind=inner (
    DeviceLogonEvents
    | where TimeGenerated > ago(lookbackTime)
    | where ActionType == "LogonSuccess"
    | project
        AccountName,
        DeviceName,
        SuccessTime = TimeGenerated,
        SuccessIP = RemoteIP,
        SuccessLogonType = LogonType
) on AccountName, DeviceName
| extend SuccessWindowEnd = LastFailure + successWindow
| where SuccessTime >= LastFailure and SuccessTime <= SuccessWindowEnd
| project
    Account = AccountName,
    Device = DeviceName,
    SuccessfulLogonTime = SuccessTime,
    FailedAttemptCount = FailedCount,
    FirstFailureTime = FirstFailure,
    LastFailureTime = LastFailure,
    FailureIPs,
    SuccessIP,
    FailureLogonTypes = LogonTypes,
    SuccessLogonType,
    AlertName = "Endpoint Brute Force Followed by Successful Logon",
    AlertSeverity = "High"

```
#### Query Explanation:

#### *1. Define Detection Parameters*
```
let failedThreshold = 10;
let lookbackTime = 1h;
let successWindow = 3m;

```
- failedThreshold: Minimum number of failed logon attempts required to trigger detection.
- lookbackTime: Time window in which failed and successful logons are evaluated.
- successWindow: Maximum time allowed between the last failed attempt and a successful logon.

#### *2. Collect Failed Logon Events*
```
DeviceLogonEvents
| where DeviceName contains "MM-atomicred-vm"
| where TimeGenerated > ago(lookbackTime)
| where ActionType == "LogonFailed"

```
- Queries endpoint authentication telemetry from Microsoft Defender for Endpoint. ie DeviceLogonEvents
- Limits results to a specific device. *`For this demonstration.`*
- Filters for failed logon attempts within the last hour.

#### *3. Aggregate Failed Attempts by Account and Device*
```
| summarize
    FailedCount = count(),
    FirstFailure = min(TimeGenerated),
    LastFailure = max(TimeGenerated),
    FailureIPs = make_set(RemoteIP, 10),
    LogonTypes = make_set(LogonType, 5)
    by AccountName, DeviceName
```
- Groups failed logons by account and device.
- Counts the number of failures.
- Captures:
  - Time of first and last failure
  - Source IP addresses used
  - Logon types (e.g., RDP, Network, Interactive)

>  This part of the query captures and limits the unique source IP addresses involved in failed logon attempts, enriching the alert with high-value investigation context.

#### *4. Apply the Brute-Force Threshold*
```
| where FailedCount >= failedThreshold

```
- Filters to accounts that experienced 10 or more failed logon attempts.
- Reduces noise and focuses on high-confidence brute-force activity.

#### *5. Correlate With Successful Logons.*
```
 join kind=inner (
    DeviceLogonEvents
    | where TimeGenerated > ago(lookbackTime)
    | where ActionType == "LogonSuccess"
) on AccountName, DeviceName

```
- Joins failed logon data with successful logon events.
- Correlation is performed on the same account and device.

#### *6. Validate the Time Correlation.*
```
| extend SuccessWindowEnd = LastFailure + successWindow
| where SuccessTime >= LastFailure and SuccessTime <= SuccessWindowEnd

```
- Checks that the successful logon occurred shortly after the last failed attempt.
- Confirms the attack pattern of:
  > Brute force --> Login Success

#### *7. Project/Display Output*
```
| project
    Account,
    Device,
    SuccessfulLogonTime,
    FailedAttemptCount,
    FirstFailureTime,
    LastFailureTime,
    FailureIPs,
    SuccessIP,
    FailureLogonTypes,
    SuccessLogonType,
    AlertName,
    AlertSeverity

```
- Outputs enriched, analyst-ready fields for alerting.
- Includes contextual data to support triage and investigation.

Under 'Incident setting' and 'Automated response', nothing needs to be changed. Click Review and Create

On the Sentinel main page, click on Automation, then create new Automation rule

![image alt](https://github.com/Muts256/SNC-Public/blob/39441ff01a4ec03995246e809b0cc7b3f0b27a2e/Images/Sentinel-Automation/Sr8.png)

Under Trigger, select what the trigger should be in  this case: When the incident is created

![image alt](https://github.com/Muts256/SNC-Public/blob/08f729e67089f862f952eb191b522cec05abe3bc/Images/Sentinel-Automation/Sr2.png)

Under Action, add a series of actions that will be executed when the rule is triggered
- Assign Owner --> select analyst 
- Change severity --> High
- Change status --> Active
- Add task --> Give the Title of Task, give a description of how the incident should be handled
  
![image alt](https://github.com/Muts256/SNC-Public/blob/39441ff01a4ec03995246e809b0cc7b3f0b27a2e/Images/Sentinel-Automation/Sr9.png)

Save the automation rule.

When the rule is triggered, check the incident activity log  to ensure that all the actions were taken

![image alt](https://github.com/Muts256/SNC-Public/blob/08f729e67089f862f952eb191b522cec05abe3bc/Images/Sentinel-Automation/Sr6.png)

The assigned analyst can then follow the NIST 800-61 Incident Response guidelines to solve the case to completion.

`Preparation` – Establishes policies, procedures, tools, and trained personnel to ensure the organization is ready to detect, analyze, and respond to security incidents. This phase is covered in the automation rule creation

`Detection and Analysis*` – Involves identifying potential security incidents, analyzing alerts and logs, and determining the scope, impact, and severity of the event. When the automation rule is triggered

`Containment, Eradication, and Recovery` – Focuses on limiting the spread of the incident, removing the threat from affected systems, and restoring normal operations securely. Includes isolating the device, account credentials, and removing any installations that may have been made by the attacker

`Post-Incident Activity` – Conducts lessons learned, documentation, and process improvements to strengthen defenses and improve future incident response capabilities. Record all the activities that were performed to completion

#### Lessons Learned

- Correlating multiple failed logons with a subsequent successful login significantly improves detection confidence and reduces false positives.
- Near real-time (NRT) analytics enable faster identification of active credential compromise attempts.
- Proper threshold and time-window tuning is essential to balance alert accuracy and noise.
- Alert enrichment with contextual data (IPs, logon types, devices) speeds up SOC triage and investigation.
- Detection logic requires continuous tuning to account for legitimate user behavior and misconfigured services.
