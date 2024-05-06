![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/4799cbed-9b4b-42a1-b531-6b4c81ab016a)

# Azure Sentinel: Live Honeynet trap and Cloud Network Hardening
Hector M. Reyes | SOC Analyst:

## Introduction
We will establish a honeynet within our Microsoft Azure Security Information and Event Management (SIEM) system to attract malicious actors worldwide and provoke live attacks on our cloud environment. Our Security Operations Center (SOC) will log, monitor, and analyze the malicious traffic generated, enabling us to conduct incident response effectively. Subsequently, we will implement stringent hardening controls, ensure compliance with regulatory standards such as NIST 800-53, and adhere to Microsoft Defender for Cloud recommendations to fortify the security of our cloud infrastructure.

![storage_explorer_web](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/70416dd1-70eb-4933-a0c7-f0a341276abb)


## Objective:
Over 24 hours, we observed attacks from various locations globally targeting our Cloud environment, encompassing Windows Virtual Machines, SQL Servers, and Ubuntu Linux VMs. Log Analytics was employed to ingest logs from diverse sources, empowering Microsoft Sentinel to construct attack maps, trigger alerts, and initiate incident responses. Microsoft Defender for Cloud served as a crucial data source for Log Analytics Workspace (LAW) and aided in evaluating the configuration of Virtual Machines in alignment with regulatory frameworks and security controls. I configured log collection within the vulnerable environment, established security metrics, and monitored the environment continuously for 24 hours. Following an investigation into the incidents flagged by Microsoft Sentinel during this timeframe, security controls were implemented to mitigate the identified threats and bolster the environment based on Microsoft Defender's recommendations. After another 24-hour monitoring phase, new metrics were gathered post-remediation, followed by the adoption of NIST 800-53 standards as a foundational framework to enhance the security posture of our cloud environment.



## Methodology:
Part 1: Environment Setup and Initial Assessment 
- Deployment of Vulnerable Virtual Machines: I initiated the project by deploying several virtual machines with known vulnerabilities on Azure to simulate an insecure cloud environment. This setup aimed to mirror an insecure cloud environment closely.

Part 2: Log Data Configuration and Collection
- Configuration of Azure for Log Data Collection: Azure was meticulously set up to collect log data from various sources. This data was then stored in a log analytics workspace, ensuring a comprehensive repository of system activities and potential security threats.

Part 3: Monitoring and Benchmarking
- 24-Hour Monitoring and Benchmarking: Over 24 hours, I actively monitored the environment, focusing on capturing critical security metrics. This phase was crucial for establishing a benchmark, which would later serve as a comparative baseline to gauge the effectiveness of implemented security enhancements.

Part 4: Incident Detection and Response
- Utilization of Microsoft Sentinel for Threat Detection: Leveraging Microsoft Sentinel, I developed attack maps, triggered alerts, and generated incidents based on the collected log data. This proactive approach allowed for the timely identification and addressing of security incidents and vulnerabilities.

Part 5: Security Enhancement Implementation
- Implementation of Security Best Practices: After identifying security issues in our environment, I improved our security posture by implementing best practices, incorporating Azure-specific recommendations, and integrating NIST SP 800-53 Revision 5 for Security Controls and NIST SP 800-61 Revision 2 for Incident Handling Guidance. The goal was to enhance the security of our cloud environment and make it more resilient against potential threats.

Part 6: Post-Remediation Assessment and Evaluation
- Reassessment and Evaluation of Security Enhancements: During the final phase, I conducted a 24-hour assessment of the environment to evaluate the security metrics after the remediation. This reassessment was critical in comparing the initial and current security states to quantify the progress and effectiveness of the implemented security enhancements.

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

- To bolster your project's security, comprehending and anticipating the strategies employed by cyber adversaries is imperative. This objective can be met by setting up a controlled virtual environment that is deliberately exposed to the public. This approach entices potential hackers, allowing them to observe and analyze their attack methods.
- In the project's preparatory phase, we implemented a dual setup: a Windows virtual machine equipped with an SQL database and a Linux server configured with loosely regulated network security groups (NSGs) to increase their visibility on the internet. Additionally, a storage account and a critical vault with publicly accessible endpoints were established to lure cyber attackers.
- Throughout this initial phase, Microsoft Sentinel was utilized to oversee the environment, leveraging logs collected by the Log Analytics workspace to monitor activities.
- This strategic gathering of intelligence provides reassurance about the thoroughness of our process, offering invaluable insights into potential vulnerabilities and security threats and enabling the formulation of robust defense mechanisms before deploying the final solution. Allow All configured.
- A storage account and critical vault were deployed with public endpoints visible on the open internet to entice these attackers even further. In this stage, Microsoft Sentinel monitored the unsecured environment using logs aggregated by the Log Analytics workspace.

## Architecture After Hardening / Security Controls

![Cloud Honeynet / SOC](https://i.imgur.com/ShquQ5C.jpg)
The architecture was fortified in the project's subsequent phase to meet NIST SP 800-53 Rev4 SC-7(3) Access Points' strict requirements. The following security enhancements were employed:  
1. Enhanced Network Security Groups (NSGs): They thoroughly block all traffic except that from pre-authorized public IP addresses. 
2. Optimized Built-in Firewalls: Carefully tailored firewall rules significantly reduced potential avenues of attack. 
3. Transition to Private Endpoints: Replaced Public Endpoints with Private Endpoints to restrict access to critical Azure resources exclusively. These enhancements fortified the architecture against potential threats and ensured compliance with security standards, laying a robust foundation for a secure digital environment.

## Microsoft Defender for Cloud | Security posture

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/343d9f0f-4a53-49c6-b540-0ae7bf918b2e)





## NSG ALLOWED MALICIOUS INBOUND FLOWS
![Cloud Honeynet / SOC](https://i.imgur.com/teF7FNx.jpg)

## LINUX SSH/SYSLOG AUTHENTICATION FAILS
![Cloud Honeynet / SOC](https://i.imgur.com/qUyipqj.jpg)

## MMSL-AUTH-FAIL
![Cloud Honeynet / SOC](https://i.imgur.com/48AltfS.jpg)

## WINDOWS RDP/SMB AUTHENTICATION FAILURES
![Cloud Honeynet / SOC](https://i.imgur.com/DEynYqT.jpg)

## MS SQL SERVER AUTHENTICATION FAILURES
![Cloud Honeynet / SOC](https://i.imgur.com/48AltfS.jpg)

## Analysis & Incident Assessment 
I carefully reviewed multiple incidents over 24 hours in a vulnerable environment. For each incident, I thoroughly examined details regarding the attackers, including their IP addresses, the methods they used, the nature of their attacks, and the sequence of events. Additionally, I looked deeper into the IP addresses to scrutinize any associated alerts, distinguish between true and false positives, and accurately assess each incident.
Incident ID: 329
- It has been reported that an attack occurred at IP address 74.249.102.160. This IP address was found to be associated with multiple incidents, which triggered several alerts and automatically created incidents.
Here is a list:
- Alert 1: Brute Force ATTEMPT – Windows; ID: 205
- Alert 2: Brute Force ATTEMPT - MS SQL Server; ID: 214
- Alert 3: Brute Force Success - Linux Syslog; ID: 329

Remediated by: Resetting the password for the compromised user and Locked down NSGs

Impact : The account was local to the Linux machine and non-admin, so it had a low impact. However, NSG hardening will remediate the attacks that have resulted in many other incidents.

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/2fa96acc-9a23-44a0-87a3-e1d74ac72856)

![NSG Allowed Inbound Malicious Flows](https://i.imgur.com/Jv8Qaf8.png)<br>


## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
Start Time 2024-05-02 10:57:29
Stop Time 2024-05-13 11:04:29

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 221542
| Syslog                   | 2310
| SecurityAlert            | 0
| SecurityIncident         | 662
| AzureNetworkAnalytics_CL | 1742

## Attack Maps Before Hardening / Security Controls

```All map queries actually returned no results due to no instances of malicious activity for the 24-hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we applied security controls:
Start Time 2024-05-04 12:37
Stop Time	2024-05-04 15:37

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 50
| Syslog                   | 2
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

![image](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/62329081-34b3-4531-be9a-ea4ed3af3cf7)



## Conclusion

A honeynet was set up on Microsoft Azure to attract real-time attacks from potential threat actors. Various log sources were integrated into a Log Analytics workspace. Using these logs, Microsoft Sentinel generated alerts, created incidents, and marked them on our Sentinel map. Furthermore, security metrics were evaluated in this vulnerable setup before and after applying specific security protocols. The results showed a significant decrease in security events and incidents, thanks to adopting selected NIST SP 800-53 guidelines and Microsoft Defender's insights. This highlights the effectiveness of the implemented security measures, which provide a positive assurance for the security posture of our Azure infrastructure.


![Synapse-Animation_Embargoed](https://github.com/reyestech/Azure-Honeynet-and-Sentinel-Hardening-/assets/153461962/6f463eb3-2e28-4023-94c2-9c85e56b23e9)



