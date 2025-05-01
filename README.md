<p align="center">
  <img src="https://github.com/user-attachments/assets/544ac8c3-8ffc-44c3-b9fd-347a20dfe786" alt="ezgif-7650866c6a50db" width="900"/>
</p>

# Azure Services: Sentinel Live Honeynet and Network Hardening
Hector M. Reyes | SOC Analyst:

 ### [Google Docs Link | Azure Honeynet and Sentinel Network Hardening](https://docs.google.com/document/d/1TbSMzlBtGITVFOTaBGqKXjKY0mPG14p5ZWra-Tj8WNk/pub)

Azure Sentinel: Live Honeynet trap and Sentinel Network Hardening

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb)


# Introduction
We will establish a honeynet within our Microsoft Azure Security Information and Event Management (SIEM) system to attract malicious actors worldwide and provoke live attacks on our cloud environment. Our Security Operations Center (SOC) will log, monitor, and analyze the malicious traffic generated, enabling us to conduct incident response effectively. Subsequently, we will implement stringent hardening controls, ensure compliance with regulatory standards such as NIST 800-53, and adhere to Microsoft Defender for Cloud recommendations to fortify the security of our cloud infrastructure.

## Objective:
Over 24 hours, we observed attacks from various locations globally targeting our cloud environment, encompassing Windows Virtual Machines, SQL Servers, and Ubuntu Linux VMs. Log Analytics was employed to ingest logs from diverse sources, empowering Microsoft Sentinel to construct attack maps, trigger alerts, and initiate incident responses. Microsoft Defender for Cloud served as a crucial data source for the Log Analytics Workspace (LAW) and aided in evaluating the configuration of virtual machines in alignment with regulatory frameworks and security controls. I configured log collection within the vulnerable environment, established security metrics, and monitored the environment continuously for 24 hours. Following an investigation into the incidents flagged by Microsoft Sentinel during this timeframe, security controls were implemented to mitigate the identified threats and bolster the environment based on Microsoft Defender's recommendations. After another 24-hour monitoring phase, new metrics were gathered post-remediation, followed by the adoption of NIST 800-53 standards as a foundational framework to enhance the security posture of our cloud environment.

![storage_explorer_web](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb)
![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9859c84f-cf7b-4ccb-8ad7-4bf2dd5a35cb)

## Methodology:
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

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9e373532-29bd-40c3-8b4c-39569133f645)
## Methodology:
Infrastructure Setup
Azure Virtual Network (VNet): 
- The foundational network layer in Azure.
- Virtual Machines (2 Windows VMs, 1 Linux VM): The compute resources where applications and services run.
- Azure Storage Account: Provides scalable cloud storage for data, applications, and workloads.

Security and Compliance
- Azure Network Security Groups (NSG): Controls inbound and outbound traffic to Azure resources.
- Azure Key Vault: Manages and protects cryptographic keys and other secrets used by cloud apps and services.
- Microsoft Defender for Cloud: Offers integrated security monitoring and policy management across Azure resources.
- NIST SP 800-53 Revision 5 for Security Controls provides a catalog of security and privacy controls for federal information systems and organizations.
- NIST SP 800-61 Revision 2 for Incident Handling Guidance offers guidance on effectively responding to and managing incidents.

Management and Operations
- Microsoft SQL Server on VMs: A relational database server is used for various transactional and analytical operations.
- SQL Server Management Studio (SSMS): An integrated environment for managing any SQL infrastructure.
- Azure Active Directory: Microsoft's multi-tenant, cloud-based directory and identity management service.
- PowerShell: A task automation and configuration management framework.
- Command Line Interface (CLI): Users can interact with their computer's operating system or software by typing commands.

Monitoring and Analysis
- Log Analytics Workspace with Kusto Query Language (KQL) Queries is a tool for collecting, searching, and analyzing log data.
- Microsoft Sentinel (SIEM) provides security information and event management, including threat detection, proactive hunting, and threat response.
- Syslog (Linux Event Logs) and Windows Event Viewer are tools for logging and analyzing system events on Linux and Windows systems, respectively.


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

## Analysis & Incident Assessment 
I carefully reviewed multiple incidents over 24 hours in a vulnerable environment. For each incident, I thoroughly examined details regarding the attackers, including their IP addresses, the methods they used, the nature of their attacks, and the sequence of events. Additionally, I looked deeper into the IP addresses to scrutinize any associated alerts, distinguish between true and false positives, and accurately assess each incident.
Incident ID: 329
- It has been reported that an attack occurred at IP address 74.249.102.160. This IP address was found to be associated with multiple incidents, which triggered several alerts and automatically created incidents.
Here is a list:
- Alert 1: Brute Force ATTEMPT – Windows; ID: 205
- Alert 2: Brute Force ATTEMPT - MS SQL Server; ID: 214
- Alert 3: Brute Force Success - Linux Syslog; ID: 329

  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/2fa96acc-9a23-44a0-87a3-e1d74ac72856" width="300"/>
  <img src="https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/9d31a24c-d5b6-41b5-9089-7675844cf60d" width="700"/>


### Azure Investigation Graph 
![image](https://github.com/user-attachments/assets/0b4fd94a-d8f0-46ab-b832-5fdfe0c2858c)


### Application and NSG hardening 
Remediated by associating and resetting the password for the compromised users and locking down NSGs
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



