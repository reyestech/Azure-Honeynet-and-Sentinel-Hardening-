<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="ezgif-7650866c6a50db" width="900"/>
</p>

# Azure: Sentinel Honeynet and Network Hardening
 **Hector M. Reyes | SOC Analyst** |  [Google Docs Version](https://docs.google.com/document/d/1TbSMzlBtGITVFOTaBGqKXjKY0mPG14p5ZWra-Tj8WNk/pub)

---

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb" width="700">
</p>

<h1 align="center"> 🔰 Introduction & Methodology </h1>


## Introduction

This report summarizes a cybersecurity analysis conducted in a live Microsoft Azure environment to capture real-world cyber threats. A honeynet of intentionally vulnerable Windows, Linux, and SQL Server virtual machines was deployed, attracting unauthorized activity from global threat actors. The primary goal was to observe malicious behavior and analyze attack patterns while implementing effective defenses based on best practices.

Using Microsoft Sentinel as the primary Security Information and Event Management (SIEM) tool, threat data was ingested and visualized in real-time. Insights from Microsoft Defender for Cloud, guided by the NIST SP 800-53 framework, helped identify vulnerabilities and apply hardening controls.

The engagement highlights advancements in security monitoring, incident response, and compliance-driven remediation, emphasizing their importance for Security Operations Center (SOC) analysts and Governance, Risk, and Compliance (GRC) functions. Findings were validated through post-remediation monitoring to enhance the environment's overall security posture.

## 🧪 **Methodology**

Our six-phase lifecycle transforms an intentionally vulnerable Azure footprint into a self-defending cloud workload, ensuring that all lessons learned are fed back into automated protection.

| Phase | Objective | Key Actions |
|-------|-----------|-------------|
| **1. Exposed Environment** | Attract live threats | Deploy Windows, Linux & SQL VMs with public IPs and permissive NSGs. |
| **2. Log Integration** | Centralize telemetry | Route diagnostics to **Azure Log Analytics**; onboard **Microsoft Sentinel** & **Defender for Cloud**. |
| **3. Baseline Threat Monitoring (24 h)** | Quantify risk | Observe malicious traffic and authentication failures to establish statistical baselines. |
| **4. Detection & Automated Response** | Halt live attacks | Create Sentinel analytics rules & playbooks aligned with **NIST SP 800-61** to isolate or block IOCs in real time. |
| **5. Security Hardening** | Shrink attack surface | Apply Microsoft and **NIST SP 800-53** controls (network segmentation, MFA, patching, PAM). |
| **6. Post-Hardening Assessment & Continuous Defense** | Prevent recurrence | Re-monitor for 24 h, compare metrics, and convert new findings into updated playbooks, TI blocklists, and policy-as-code to stop future attacks. |

---

## 📉 Initial Posture

Initial analysis from Microsoft Defender for Cloud showed a low Secure Score. Most issues are related to identity protection, endpoint configuration, and a lack of resource-level segmentation.

- Security Score: The Azure environment initially scored 34%, with critical Defender recommendations for enabling multi-factor authentication (MFA), reducing exposed endpoints, and applying OS-level patches.

- NIST SP 800-53 R5 Access Control (AC) Findings: The setup lacked enforced role-based access, secure defaults, and audit logging—violating core NIST controls under the Access Control (AC) family.

<h3 align="center">📂 Secured Storage Access via Private Endpoint </h3>

<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb" width="700">
</p>

## Initial-Attacks-Surface
### 🛡️Microsoft Defender for Cloud 

Microsoft Sentinel's built-in geospatial map feature revealed rapid inbound scanning activity. Within 24 hours, the environment had attracted thousands of connection attempts, primarily from Brazil, China, and Russia, highlighting how quickly attackers target new Azure resources with open ports.

Overview: Initial assessment revealed a low security posture and a lack of compliance with access control standards.
  - Security Score:

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/343d9f0f-4a53-49c6-b540-0ae7bf918b2e" width="400">
</p>

  - NIST SP 800-53 R5 – Access Control (AC) Findings:
> AC. Access Control: In access control, we can see what is missing to meet NIST standards.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/1a89ae0f-1d81-47b7-852d-b66cdafb0748" width="600">
</p>

<p align="left">
  <img src="https://github.com/user-attachments/assets/b79fc23a-764b-4b23-afe5-2962621f2e6b" width="600">
</p>

---

## 🌍 Sentinel Maps: Monitoring Active Cyber Threats
> Cyber Threat Landscape: Visualizing Live Cyberattacks with Sentinel Maps
## Initial Maps 

## 1. NSG-Inbound
### 🌐 **Network Security Groups (NSG)** – Malicious Inbound Flows

This query identifies potentially malicious inbound traffic targeting your environment through Azure Network Security Groups (NSGs). It focuses on flows categorized as malicious that have been allowed access to your virtual network, often from untrusted or unidentified threat IPs.

Monitoring this traffic is crucial for security teams to detect early signs of compromise, including reconnaissance scans or brute-force attacks. Analysts can streamline threat investigations by presenting key information like source and destination IP addresses and timestamps.

<details>
  <summary><strong>⚙ How NSG Traffic Query Works: Click to View </strong></summary>

**NSG Traffic Query Table:**

- **Table**: `AzureNetworkAnalytics_CL` – This custom log table contains flow-level analytics and metadata from Azure NSGs.
- **Filter**:
  - `FlowType_s == "MaliciousFlow"` – Filters for traffic labeled as malicious based on threat intel or behavioral analysis.
  - `AllowedInFlows_d >= 1` – Ensures the query only returns entries where **inbound flows were allowed**, indicating a potential exposure.
- **Output**:
  - `TimeGenerated`: When the traffic occurred  
  - `SrcIP_s`: The originating (possibly malicious) IP  
  - `DestIP_s`: The destination IP within your environment  

</details>

> NSG received inbound traffic from untrusted IPs.

<details>
   <summary><strong> 📋Click to View Query: NSG Traffic </strong></summary>
     
KQL Query: NSGs Inbound Traffic from all untrusted IPs.
```kql
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d >= 1
| project TimeGenerated, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/04e1dffa-958e-4d1c-b326-dc75a3ca91df)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/73cc9fbe-f8b9-4593-b40f-f4a485c9150b" width="600">
</p>

## 🐧2. Linux SSH Attacks – Authentication Failures

SSH services on Ubuntu servers faced persistent brute-force login attempts. Sentinel flagged multiple password failures from a small set of rotating global IPs.

* **Phase 1:** Detection began with hundreds of "Failed password" messages in the Syslog stream.
* **Phase 2:** Analysts used automation to isolate attacker IPs and block them at the NSG level. These attacks slowed significantly post-hardening.

> **Description:** Detected failed SSH login attempts targeting Ubuntu VM.

 <details>
   <summary><strong> 📋Click to View Query: SSH Attacks </strong></summary>
   
🔹KQL Query: SSH Authentication Fails for Linux VMs
```kql
Syslog
| where Facility == "auth" and SyslogMessage contains "Failed password"
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/067e7d93-2757-4375-8d27-4b3472a9900c)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/f722c441-841d-4044-9181-3f2cea84a558" width="600">
</p>


## 🪟 3. Windows RDP Attacks – SMB/RDP Authentication Failures
Attackers repeatedly targeted exposed Windows VMs through port 3389 using common usernames and password variations. These brute-force attempts triggered Sentinel rules after reaching detection thresholds.

* **Phase 1:** Failed logons were seen in `SecurityEvent` logs, marked with EventID 4625 and logonType 10 (RDP).
* **Phase 2:** Accounts were protected by enabling lockouts and narrowing NSG rules.

> **Description:** Observed brute-force attempts via RDP/SMB protocols on Windows VMs.

 <details>
   <summary><strong> 📋Click to View Query: SMB/RDP Attacks </strong></summary>
   
🔹KQL Query: SMB/RDP Authentication Fails for Windows VMs
```kql
SecurityEvent
| where EventID == 4625
| where LogonType == 10
```

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/13021670-248a-4aa0-8266-deb373dfd6a7)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/97d93c53-713c-4857-9643-a3149a2317f0" width="600">
</p>


## 🛢️ 4. SQL Server Attacks – Authentication Failures

SQL Server faced login brute-force attempts through unauthenticated probes aimed at default accounts like sa. Sentinel registered spikes in failed logins and clustered alerts from similar IP ranges.

Phase 1: SQL logs highlighted repeated login failures often spaced in short intervals.
Phase 2: Sentinel playbooks were deployed to quarantine source IPs and notify security teams.

> **Description:** Repeated failed login attempts targeting exposed SQL Server.

<details>
  <summary><strong> 📋Click to View Query: SQL Attacks </strong></summary>

🔹KQL Query: SQL Server Authentication Fails
```kql
// Failed SQL logins
SqlSecurityAuditEvents
| where action_name == "FAILED_LOGIN"
```
  
  ![image](https://github.com/user-attachments/assets/06872696-6720-4d20-8d54-68233c7ab16d)

</details>

<p align="left">
  <img src="https://github.com/user-attachments/assets/a687ffa2-0469-4f4a-a54b-8758583b7985" width="600">
</p>

---

## Analysis & Incident Assessment 
This section highlights how Microsoft Sentinel was used to investigate and respond to coordinated brute-force attacks across Windows, SQL Server, and Linux systems within a 24-hour monitoring period.
**Incident ID: 329** Wass linked to malicious IP 74.249.102.160, which triggered multiple alerts.
> 1. **Alert 205:** Brute Force Attempt – Windows
> 2. **Alert 214:** Brute Force Attempt – MS SQL Server
> 3. **Alert 329:** Brute Force Success – Linux Syslog

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/2fa96acc-9a23-44a0-87a3-e1d74ac72856" width="350"/> 


## **Analyzing the Traffic** 

Sentinel analytics helped correlate these events, enabling detailed examination of attacker behavior, IP reputation, and sequence of actions. I analyzed both successful and failed attempts, filtering out false positives and tracking escalation patterns.

📊 **The included visuals show:**
> 1.	Sharp spikes in brute-force login attempts during the vulnerable phase
> 2.	NSG flow logs mapping inbound malicious traffic
> 3.	Timelines that illustrate how these threats stopped once hardening controls were applied

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9d31a24c-d5b6-41b5-9089-7675844cf60d" width="600"/> 

✅ **Result:** Sentinel detections and NSG rule adjustments significantly reduced the attack surface and prevented further compromise. 


## **Azure Investigation Graph**

Microsoft Sentinel’s Investigation Graph stitches all elements—hosts, alerts, IPs, and user actions—into a single navigable chain. This visualization helped responders understand event sequences and attribution.

> Connecting alerts, affected hosts, and user accounts in a unified timeline. This enables analysts to swiftly transition from one indicator to corresponding evidence, enhancing the speed of triage and root-cause analysis.

<img src="https://github.com/user-attachments/assets/0b4fd94a-d8f0-46ab-b832-5fdfe0c2858c" width="50%" />

## **Application and NSG hardening**
Remediated by associating and resetting the passwords for the compromised users and locking down NSGs
> Impact: The account was local to the Linux machine and non-admin, so it had a low impact. However, NSG hardening will remediate the attacks that have resulted in many other incidents.

  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/23a192c8-65d3-4dc7-8112-d57e522eefac" width="600"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/ea612103-e77f-4529-be2a-c867c3c3f7aa" width="600"/>

---

# 📊 Post-Hardening Attack Surface 

All map queries returned no results because there was zero malicious activity during the 24 hours following hardening.
After implementing hardening measures, we detected no malicious activity. All queries on the Sentinel map returned zero results, confirming the effectiveness of tightening our Network Security Groups (NSGs), utilizing private endpoints, and adhering to compliance requirements. By following Microsoft-recommended hardening steps alongside NIST SP 800-53 controls, we successfully reduced malicious traffic and incidents to zero within 24 hours.
<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/727edb36-b4e2-448d-aed0-60b5484ae91e" alt="No incidents after hardening" width="600"/>
</p>


### 🔐 VLAN and Subnet Configuration

These visuals demonstrate how the lab's single virtual network was divided into **three purpose-built subnets**. These subnets act as isolation zones, restricting traffic and limiting the blast radius if an attacker compromises a single host.

**Azure Topology:** The Azure topology view displays all virtual machines (VMs), databases, and gateways on a single subnet within a virtual network. These subnets are separate rooms within the same building, each with doors (network security groups) that can be locked individually. The resource list in the right-hand pane is filtered by subnet, confirming that web, SQL, and management workloads reside in their segments.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/67ba9152-de43-4345-82fd-92b2da05b9f2" alt="Subnet config 1" width="330"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/fa608462-bba8-4dea-975a-5c9fc9905081" alt="Subnet config 2" width="340"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/49cb6ca9-e3d9-4bd5-bea5-44e0a19cc78a" alt="Subnet config 3" width="330"/>
</p>

---

### 🧰 Azure NIST Overview
NIST SP-800-53 is a comprehensive guideline for security and privacy controls in federal information systems. It is the foundation for compliance frameworks like FedRAMP, CSF, and Azure Security Benchmark.
To check NIST SP-800-53-R5 compliance:
> Navigate to: **Azure Home > Microsoft Defender for Cloud > Regulatory compliance > NIST SP-800-53-R5**
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/00b13f92-53cb-4cec-a630-d168dcec4542" alt="Defender compliance 1" width="700"/>

## 🧰 Azure NIST Overview

| Stage         | Key Actions                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------- |
| **Build**     | Develop security framework using the NIST SP 800‑53 workbook as a foundational guide.              |
| **Assess**    | Conduct assessments using Microsoft Sentinel and Defender to identify misconfigurations and risks. |
| **Remediate** | Implement Azure DDoS Protection, restrict Network Security Groups (NSGs), and enforce access controls.                       |
| **Monitor**   | Continuously oversee security controls and telemetry within Defender and Sentinel.                 |
| **Respond**   | Use automated playbooks to notify governance teams and log all critical incidents.                 |

> Navigate to: **Azure Home → Defender for Cloud → Regulatory Compliance → NIST SP‑800‑53‑R5**

NIST SP‑800‑53 is a comprehensive guideline for security and privacy controls in federal systems. It underpins compliance programs such as FedRAMP, CSF, and Azure Security Benchmark. This approach promotes continuous risk management across the security lifecycle and enhances cloud resilience.


This systematic approach promotes effective management of security controls throughout their lifecycle, ensuring organizational resilience against potential threats.

<p align="center">
<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/821b1360-c5c8-4606-bd1b-f274761594a3" width="65%">
</p>

---

# Project Architecture Overview

## Architecture-Before-Hardening

### 🔓 **Initial Architecture (Insecure)**
The initial cloud architecture was an intentionally misconfigured Azure environment designed to simulate a high-risk production workload. This setup served as a honeynet to attract live cyber threats, gather telemetry, and observe adversary behavior.
1. **Public Exposure of Critical Resources:** Deployment included Windows and Linux Virtual Machines, an SQL Server, a storage account, and a key vault with public-facing endpoints.
2. **Permissive Network Security Groups (NSGs):** Default and loosely configured NSG rules allowed unrestricted inbound traffic, creating vulnerabilities to scanning, brute-force attacks, and lateral movement.
3. **Initial Monitoring via Microsoft Sentinel:** Logs from all resources were systematically collected through Azure Log Analytics and monitored using Microsoft Sentinel to detect real-time alerts, failed authentication attempts, and reconnaissance activities.

<div align="center">
  <img src="https://github.com/user-attachments/assets/f5ec8a80-09b3-42a4-ac2b-8f6cfb5d2918" width="70%" />
</div>

> Public-facing VMs & services are  exposed and attract attackers.

## Architecture-After-Hardening

### 🔓 **Hardened Architecture (Secure & Compliant)**
Following the initial threat analysis, the environment was meticulously restructured to align with secure architecture principles and NIST SP 800-53 controls, particularly SC-7(3) for Access Restrictions. Key enhancements focused on drastically minimizing external exposure and strengthening infrastructure:

1. **Restricted Access via Hardened NSGs:**  Ingress traffic was rigorously controlled, permitting access exclusively from specific, trusted public IP addresses while blocking all other external traffic.
2. **Replacement of Public Endpoints with Private Endpoints:** Critical resources (e.g., storage, key vault) were migrated to Azure Private Endpoints, ensuring access is restricted solely to trusted virtual networks and eliminating public exposure.
3. **Enforced Firewall and Policy Controls:** Azure-native firewalls and Microsoft Defender for Cloud policies were applied to implement platform-level protection and maintain continuous compliance with SC-7(3).

<div align="center">
  <img src="https://github.com/user-attachments/assets/a8eeaf5e-f941-4db5-9a1c-dfd87f05b160" width="70%" />
</div>

> NSGs tightened, firewalls tuned, public endpoints replaced by private endpoints, controls aligned to NIST SC-7(3).

---

## Metrics & Results

> 📉 The dramatic drop in alerts, flows, and incidents demonstrates how quickly and effectively the environment improved after implementing targeted hardening strategies.

### ⏱️ Before vs After (24 h)

| Metric | Before | After | Δ % |
|--------|-------:|------:|----:|
| **Security Events** (Windows) | 221 542 | 84 | **-99.96** |
| **Syslog** (Linux)            | 2 310   | 2  | **-99.91** |
| **Security Alerts**           | 4       | 0  | **-100.00** |
| **Sentinel Incidents**        | 662     | 0  | **-100.00** |
| **Malicious NSG Flows**       | 1 742   | 0  | **-100.00** |

> 🔍 These figures confirm a complete elimination of detected attacks after hardening.

🧱 This comparison shows how exposed infrastructure was transformed into a secure environment by integrating best practices, including private endpoints and network security group (NSG) restrictions.sa

----

## Kusto Query Language (KQL) & Python SDK Automation Queries

<details>
<summary> 📋 Click to View KQL All Automation Queries <</summary>
  
### Start & Stop Time
```
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()
```
### Security Events (Windows VMs)
```
SecurityEvent
| where TimeGenerated >= ago(24h)
| count
```
### Syslog (Ubuntu Linux VMs)  
```
Syslog
| where TimeGenerated >= ago(24h)
| count
```
### Security Alert (Microsoft Defender for Cloud)
```
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count
```
### Security Incidents (Sentinel Incidents)
```
SecurityIncident
| where TimeGenerated >= ago(24h)
| count
```
### Azure NSG Inbound Malicious Flows Allowed
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```
### Azure NSG Inbound Malicious Flows Allowed
```
AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow" and DeniedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
```
</details>

---

## Conclusion
A honeynet was deployed within the Microsoft Azure environment to simulate a high-risk setting vulnerable to modern cyberattacks. Misconfigured virtual machines running Windows, Linux, and SQL Server were exposed to real-time threats. Centralized logging through Azure Log Analytics combines telemetry from various sources. At the same time, Microsoft Sentinel served as the SIEM platform, enabling real-time alerts and threat visualization through interactive workbooks and geolocation maps. Alerts were correlated with incidents, enabling structured triage workflows similar to those of a Security Operations Center (SOC).

Following a baseline analysis of threat activity, the environment was strengthened by implementing Azure-native security controls aligned with NIST SP 800-53, including critical measures such as Network Security Group lockdowns and the use of private endpoints. Microsoft Defender for Cloud assessed misconfigurations and guided remediation efforts. The monitored environment demonstrated a significant reduction in unauthorized access attempts and brute-force attacks, underscoring the importance of layered security and continuous monitoring in enhancing cloud security posture from a Security Operations Center (SOC) perspective.


<p align="center">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/6f463eb3-2e28-4023-94c2-9c85e56b23e9" width="700" alt="Methodology Infographic">
</p>
