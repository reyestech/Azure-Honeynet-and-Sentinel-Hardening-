<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="ezgif-7650866c6a50db" width="900"/>
</p>

# Azure: Sentinel Honeynet and Network Hardening
 **Hector M. Reyes | SOC Analyst:**

 ### [Google Docs Link | Azure Honeynet and Sentinel Network Hardening](https://docs.google.com/document/d/1TbSMzlBtGITVFOTaBGqKXjKY0mPG14p5ZWra-Tj8WNk/pub)


# 🔐**Introduction**  

In this project, I designed and deployed a Security Operations Center (SOC) environment using Microsoft Azure, using Microsoft Sentinel as the central Security Information and Event Management (SIEM) solution. To investigate emerging cyberattack behavior, I set up a honeynet by deploying intentionally vulnerable virtual machines running Windows, Linux, and SQL Servers, all exposed to the internet. This configuration aimed to attract malicious actors from around the globe, allowing for the collection and analysis of real-time attack data and current threat vectors.

The SOC was designed to log, monitor, and analyze malicious traffic, which facilitated effective incident response. After the initial observations, I implemented stringent hardening controls that aligned with regulatory standards, such as NIST SP 800-53. I followed recommendations from Microsoft Defender for Cloud to enhance the security posture of the cloud infrastructure.

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb)


## 🎯 **Objective**  
This project aimed to evaluate and enhance the security posture of a cloud environment through the simulation of real-world cyberattacks and the establishment of a structured incident response process. A honeynet, consisting of exposed Windows, Linux, and SQL Server virtual machines (VMs), was deployed over 24 hours to attract global cyber threats. Logs collected via Azure Log Analytics facilitated the detection of malicious activities, the generation of alerts, and the initiation of automated incident responses utilizing Microsoft Sentinel.

Microsoft Defender for Cloud was employed to assess the configurations of the VMs against established compliance benchmarks, thereby identifying existing security vulnerabilities. Following the implementation of hardening measures, an additional assessment was conducted over a 24-hour period to validate the effectiveness of these remediation efforts. The NIST SP 800-53 framework was adopted as the foundational standard to ensure long-term compliance and to strengthen the cloud environment's defenses against potential threats.

## **Methodology**
  - Part 1: Environment Setup and Initial Assessment:  
 Deployment of Vulnerable Virtual Machines: I initiated the project by deploying several virtual machines with known vulnerabilities on Azure to simulate an insecure cloud environment. This setup aimed to mirror an insecure cloud environment closely.
    
  - Part 2: Log Data Configuration and Collection:  
Configuration of Azure for Log Data Collection: Azure was meticulously set up to collect log data from various sources. This data was then stored in a log analytics workspace, ensuring a comprehensive repository of system activities and potential security threats.

  - Part 3: Monitoring and Benchmarking  
24-Hour Monitoring and Benchmarking: Over 24 hours, I actively monitored the environment, focusing on capturing critical security metrics. This phase was crucial for establishing a benchmark, which would later serve as a comparative baseline to gauge the effectiveness of implemented security enhancements.

  - Part 4: Incident Detection and Response  
Using Microsoft Sentinel for Threat Detection: By leveraging Microsoft Sentinel, I created attack maps, activated alerts, and produced incidents from the gathered log data. This proactive method facilitated the prompt detection and resolution of security incidents and vulnerabilities.

  - Part 5: Security Enhancement Implementation  
Implementation of Security Best Practices: After identifying security issues in our environment, I improved our security posture by implementing best practices, incorporating Azure-specific recommendations, and integrating NIST SP 800-53 Revision 5 for Security Controls and NIST SP 800-61 Revision 2 for Incident Handling Guidance. The goal was to enhance the security of our cloud environment and make it more resilient against potential threats.

  - Part 6: Post-Remediation Assessment and Evaluation  
Reassessment and Evaluation of Security Enhancements: During the final phase, I conducted a 24-hour assessment of the environment to evaluate the security metrics after the remediation. This reassessment was critical in comparing the initial and current security states to quantify the progress and effectiveness of the implemented security enhancements.
# **🛠️ Key Skills**  
> 1. **Azure Security Architecture:** Designed and implemented a secure cloud infrastructure within Microsoft Azure.
> 2. -**SIEM Log Analytics:** Utilized Microsoft Sentinel for real-time monitoring and analysis of security events.
> 3. -**Kusto Query Language (KQL):** Developed and executed queries for effective threat hunting and data analysis.
> 4. -**Threat Detection & Response:** Identified and responded to security incidents, enhancing the environment's resilience.
> 5. -**Vulnerability Management:** Assessed and mitigated vulnerabilities within the cloud infrastructure.
> 6. -**Compliance Governance:** Ensured adherence to regulatory standards and best practices.
> 7. -**Cloud Networking:** Configured and managed network security groups and virtual networks.
> 8. -**Automation:** Implemented automated responses to security incidents, streamlining operations.

![storage_explorer_web](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb)


## Architecture Before Hardening / Security Controls

![Cloud Honeynet / SOC](https://i.imgur.com/iSlfeYX.jpg)

- To bolster your project's security, comprehending and anticipating the strategies employed by cyber adversaries is imperative. This objective can be met by setting up a controlled virtual environment that is deliberately exposed to the public. This approach entices potential hackers, allowing them to observe and analyze their attack methods.it is imperative to comprehend and anticipate. To achieve this, you can set
- In the project's preparatory phase, we implemented a dual setup: a Windows virtual machine equipped with an SQL database and a Linux server configured with loosely regulated network security groups (NSGs) to increase their visibility on the internet. Additionally, a storage account and a critical vault with publicly accessible endpoints were established to lure cyber attackers.
- Throughout this initial phase, Microsoft Sentinel was utilized to oversee the environment, leveraging logs collected by the Log Analytics workspace to monitor activities.
- This strategic gathering of intelligence provides reassurance about the thoroughness of our process, offering invaluable insights into potential vulnerabilities and security threats and enabling the formulation of robust defense mechanisms before deploying the final solution. Allow All configured. This strategic intelligence gathering. It offers enables
To further entice these attackers, a storage account and critical vault were deployed with public endpoints visible on the open internet. At this stage, Microsoft Sentinel monitored the unsecured environment using logs aggregated by the Log Analytics workspace.

## Architecture After Hardening / Security Controls

![Cloud Honeynet / SOC](https://i.imgur.com/ShquQ5C.jpg)

The architecture was fortified in the project's subsequent phase to meet NIST SP 800-53 Rev4 SC-7(3) Access Points' strict requirements. The following security enhancements were employed:  
1. Enhanced Network Security Groups (NSGs): They thoroughly block all traffic except that from pre-authorized public IP addresses. 
2. Optimized Built-in Firewalls: Carefully tailored firewall rules significantly reduced potential avenues of attack. 
3. Transition to Private Endpoints: Replaced Public Endpoints with Private Endpoints to restrict access to critical Azure resources exclusively. These enhancements fortified the architecture against potential threats and ensured compliance with security standards, laying a robust foundation for a secure digital environment.

## Attack Maps Before Hardening / Security Controls

Microsoft Defender for Cloud: 
  - Security posture: In this section, we can see a grade showing we are not 

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/343d9f0f-4a53-49c6-b540-0ae7bf918b2e)

NIST SP 800 53 R5
  - AC. Access Control: In access control, we can see what is missing to meet NIST standards.

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/1a89ae0f-1d81-47b7-852d-b66cdafb0748)

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9196cc1a-27e9-4932-ad65-e8e00035d3de)


---

# Attack Maps Before Hardening

### Azure Network Security Group Attacks
NSG ALLOWED MALICIOUS INBOUND FLOWS
  - KQL Query to view our Azure Cloud environment's Network Security Group on the custom Map

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/04e1dffa-958e-4d1c-b326-dc75a3ca91df)


![Cloud Honeynet / SOC](https://i.imgur.com/teF7FNx.jpg)

### LINUX SSH Attacks
SYSLOG AUTHENTICATION FAILS
  - KQL Query to view attacks on our Linux Ubuntu Virtual Machine on the custom Map

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/067e7d93-2757-4375-8d27-4b3472a9900c)


![Cloud Honeynet / SOC](https://i.imgur.com/qUyipqj.jpg)


### Windows RDP Attacks
WINDOWS RDP/SMB AUTHENTICATION FAILURES
  - KQL Query to view attacks on Windows Computers on the custom Map

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/13021670-248a-4aa0-8266-deb373dfd6a7)

![Cloud Honeynet / SOC](https://i.imgur.com/DEynYqT.jpg)

### MS SQL Server Attacks
MS SQL SERVER AUTHENTICATION FAILURES
  - KQL Query to view attacks on our SQL Servers on the custom Map
    
![image](https://github.com/user-attachments/assets/5fd98698-2074-45cf-acca-27c15632e2b7)


![Cloud Honeynet / SOC](https://i.imgur.com/48AltfS.jpg)

# Analysis & Incident Assessment 

This section highlights how Microsoft Sentinel was used to investigate and respond to coordinated brute-force attacks across Windows, SQL Server, and Linux systems within a 24-hour monitoring period.

**Incident ID: 329** Wass linked to malicious IP 74.249.102.160, which triggered multiple alerts.
> 1. **Alert 205:** Brute Force Attempt – Windows
> 2. **Alert 214:** Brute Force Attempt – MS SQL Server
> 3. **Alert 329:** Brute Force Success – Linux Syslog
<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/2fa96acc-9a23-44a0-87a3-e1d74ac72856" width="350"/>

Sentinel analytics helped correlate these events, enabling detailed examination of attacker behavior, IP reputation, and sequence of actions. I analyzed both successful and failed attempts, filtering out false positives and tracking escalation patterns.
📊 **The included visuals show:**
> 1.	Sharp spikes in brute-force login attempts during the vulnerable phase
> 2.	NSG flow logs mapping inbound malicious traffic
> 3.	Timelines that illustrate how these threats stopped once hardening controls were applied

✅ **Result:** Sentinel detections and NSG rule adjustments significantly reduced the attack surface and prevented further compromise. 

<img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9d31a24c-d5b6-41b5-9089-7675844cf60d" width="700"/>


### Azure Investigation Graph 
> The Investigation Graph automatically visualizes the complete attack chain—connecting alerts, affected hosts, and user accounts in a unified timeline. This enables analysts to swiftly transition from one indicator to corresponding evidence, enhancing the speed of triage and root-cause analysis.

![image](https://github.com/user-attachments/assets/0b4fd94a-d8f0-46ab-b832-5fdfe0c2858c)


### Application and NSG hardening 
> Remediated by associating and resetting the passwords for the compromised users and locking down NSGs
Impact: The account was local to the Linux machine and non-admin, so it had a low impact. However, NSG hardening will remediate the attacks that have resulted in many other incidents.

  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/23a192c8-65d3-4dc7-8112-d57e522eefac" width="800"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/ea612103-e77f-4529-be2a-c867c3c3f7aa" width="800"/>

## 📊 Post-Hardening

All map queries returned no results due to zero malicious activity during the 24 hours following hardening.
After implementing hardening measures, we detected no malicious activity. All queries on the Sentinel map returned zero results, confirming the effectiveness of tightening our Network Security Groups (NSGs), utilizing private endpoints, and adhering to compliance requirements. By following Microsoft-recommended hardening steps alongside NIST SP 800-53 controls, we successfully reduced malicious traffic and incidents to zero within 24 hours.
<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/727edb36-b4e2-448d-aed0-60b5484ae91e" alt="No incidents after hardening" width="700"/>
</p>

---

### 🔐 VLAN and Subnet Configuration

These visuals demonstrate how the lab's single virtual network was divided into **three purpose-built subnets**. These subnets act as isolation zones, restricting traffic and limiting the blast radius if an attacker compromises a single host.
> **Azure Topology:** The topology view in Azure displays every virtual machine (VM), database, and gateway on its subnet within a single virtual network. These subnets are separate rooms within the same building, each with doors (network security groups) that can be locked individually. The resource list in the right-hand pane is filtered by subnet, confirming that web, SQL, and management workloads reside in their segments.

<p align="left">
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/67ba9152-de43-4345-82fd-92b2da05b9f2" alt="Subnet config 1" width="330"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/fa608462-bba8-4dea-975a-5c9fc9905081" alt="Subnet config 2" width="340"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/49cb6ca9-e3d9-4bd5-bea5-44e0a19cc78a" alt="Subnet config 3" width="330"/>
</p>

---

### 🧰 Azure NIST Overview
NIST SP-800-53 is a comprehensive guideline for security and privacy controls in federal information systems. It serves as the foundation for compliance frameworks like FedRAMP, CSF, and Azure Security Benchmark.
To check NIST SP-800-53-R5 compliance:
> Navigate to: **Azure Home > Microsoft Defender for Cloud > Regulatory compliance > NIST SP-800-53-R5**
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/00b13f92-53cb-4cec-a630-d168dcec4542" alt="Defender compliance 1" width="700"/>


**NIST Protection:** 
A high-level use case for implementing NIST controls involves thoroughly examining the security lifecycle. This process includes the following stages:
> 1. **Build:** Develop security frameworks using the NIST workbook as a foundational guide. 
> 2. **Assess:** Conduct assessments with tools like Sentinel to identify vulnerabilities and gaps within the security infrastructure.
> 3. **Remediate:** Implement Azure DDoS protection to address identified threats.
> 4. **Monitor:** Continuously oversee and evaluate security measures to ensure their effectiveness.
> 5. **Respond:** Utilize an automated playbook designed to notify the governance team of any security incidents.

This systematic approach promotes effective management of security controls throughout their lifecycle, ensuring organizational resilience against potential threats.

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/821b1360-c5c8-4606-bd1b-f274761594a3)

---

# Azure SIEM Harderning Summary

## Architecture

> 🧱 This side-by-side comparison highlights how exposed infrastructure was transformed into a secured environment by integrating best practices like private endpoints and NSG restrictions.

| Stage | Diagram | Description |
|-------|---------|-------------|
| **Before Hardening** | <img src="https://i.imgur.com/iSlfeYX.jpg" alt="Pre-hardening architecture" width="350"> | Public-facing VMs & services intentionally exposed to attract attackers. |
| **After Hardening**  | <img src="https://i.imgur.com/ShquQ5C.jpg" alt="Post-hardening architecture" width="350"> | NSGs tightened, firewalls tuned, public endpoints replaced by private endpoints, controls aligned to NIST SC-7(3). |



---

## Methodology

> 🔍 Each phase followed a logical progression from open exposure to complete remediation. Sentinel, Defender, and NIST guidelines were used together to identify threats and harden the environment based on real-world telemetry.

| Phase | Key Actions |
|-------|-------------|
| **1  Environment Build** | Deployed 2 Windows VMs, 1 Ubuntu VM, SQL Server, Storage Account & Key Vault with permissive NSGs. |
| **2  Log Collection**   | Enabled diagnostic settings → Log Analytics; onboarded Defender for Cloud & Sentinel. |
| **3  Baseline (24 h)**  | Captured attacks, created Sentinel alerts/incidents, stored metrics for comparison. |
| **4  Hardening**        | Applied Microsoft & NIST recommendations (NSGs, firewalls, private endpoints, IAM). |
| **5  Post-Remediation (24 h)** | Re-monitored metrics; validated 0 incidents and 0 malicious flows. |

---

## Metrics & Results

> 📉 The dramatic drop in alerts, flows, and incidents demonstrates how quickly and effectively the environment improved after targeted hardening strategies were implemented.

### ⏱️ Before vs After (24 h)

| Metric | Before | After | Δ % |
|--------|-------:|------:|----:|
| **Security Events** (Windows) | 221 542 | 84 | **-99.96** |
| **Syslog** (Linux)            | 2 310   | 2  | **-99.91** |
| **Security Alerts**           | 4       | 0  | **-100.00** |
| **Sentinel Incidents**        | 662     | 0  | **-100.00** |
| **Malicious NSG Flows**       | 1 742   | 0  | **-100.00** |

> 🔍 These figures confirm a complete elimination of detected attacks after hardening.

## Kusto Query Language (KQL) & Python SDK Automation Queries

<details>
<summary>KQL Queries Used</summary>
  
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

A honeynet was established on Microsoft Azure to draw real-time attacks from potential threat actors. Various log sources were integrated into a Log Analytics workspace. Microsoft Sentinel generated alerts using these logs, created incidents, and marked them on our Sentinel map. Additionally, security metrics were evaluated in this vulnerable setup before and after implementing specific security protocols. The results demonstrated a significant decrease in security events and incidents attributed to adopting selected NIST SP 800-53 guidelines and insights from Microsoft Defender. This outcome highlights the effectiveness of the security measures implemented, providing positive assurance regarding the security posture of our Azure infrastructure.


![Synapse-Animation_Embargoed](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/6f463eb3-2e28-4023-94c2-9c85e56b23e9)



