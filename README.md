# Real-world-cybersecurity-incident-analysis (Defender's Lens)
A structured analysis of real-world cybersecurity incidents conducted from a defender perspective. This repository examines how attacks occurred, the assets impacted, and the response and prevention strategies required to risk and improve security posture. 

This repository analyzes real-world cybersecurity incidents from a defender's perspective. It explores how attacks happened, the asssets affected, and strategies used for response and prevention, to reduce risk and strengthen the organisation security posture.

## Cybersecurity incident scenarios ##
### Yahoo data breach ###
The Yahoo data breach, which initially occured in 2013 but was publicly disclosed in 2016, remains one of the largest known data breaches in history.
This incident compromised over 3 billion user accounts and exposed personally identifiable information (PII), security question, and hashed passwords, creating a substantial impact on both Yahoo users and the broader cybersecurity community. Analyzing this breach from a defender-centric perspective provides valuable insights into attack vectors, system vulnerabilities, and preventive strategies essential for improving organizational security posture.

The breach took place in August 2013. Hackers gained unauthorized access to yahoo’s network and remained undetected for years.The breach was first disclosed publicly in December 2016, when Yahoo confirmed that approximately 1 billion accounts had been compromised. Later investigations revealed that the actual scope was even larger, ultimately affecting all 3 billion Yahoo user accounts.

The breach affected nearly every Yahoo user at the time, exposing sensitive data; like username and email adadress, telephone numbers, hashed passwords, and other data.
The breach did not directly expose financial data,but the compromised credentials allowed attackers to attempt account takeovers across multiple services where user reused passwords.


### Weakness that were exploited ###
- Weak Identity and Access Management (IAM):
 Yahoo relied heavily on single-factor authentication for internal access. Privileged systems lacked strong controls such as mandatory MFA, allowing attackers to operate using stolen credentials.

- Poor Privilege Management:
The principle of least privilege was not properly enforced. Internal accounts had broader access than necessary, enabling attackers to escalate privileges and reach sensitive systems.

- Inadequate Network Segmentation:
Yahoo’s internal network allowed lateral movement. Once inside, attackers could navigate across systems without encountering sufficient barriers or alerts.

- Outdated Cryptography (MD5 Hashing):
User passwords were stored using MD5, a cryptographically weak hashing algorithm. This allowed attackers to crack many passwords after obtaining the hashes.

- Lack of Monitoring and Detection:
The attackers remained undetected for nearly three years due to insufficient logging, monitoring, and anomaly detection.

### Threat elimination ### 

What should be done after discovering the breach.

#### Containment actions ####
  
- Immediately after discovering the breach, the following actions should be taken:

- Disable compromised internal accounts

- Revoke all affected authentication cookies

- Shut down unauthorized access paths

- Block suspicious IP addresses and sessions

#### System isolation ####
- Isolate compromised servers, especially identity and authentication systems

- Remove affected systems from production environments

- Preserve forensic evidence for investigation

  #### Credential resets ####
- Force password resets for all affected users

- Reset internal administrative credentials

- Invalidate security questions and answers

  #### Patching ####
- Patch all known vulnerabilities

- Remove outdated authentication mechanisms

- Harden access to identity infrastructure

  #### Malware removal ####
  
- Scan isolated systems for malware or backdoors

- Remove persistence mechanisms

- Rebuild systems where integrity cannot be guaranteed

### Threat prevention ###
#### Implementation of security controls ####
* Enforce multi-factor authentication for all internal and privileged access

* Use modern password hashing algorithms (bcrypt, Argon2)

* Encrypt sensitive data at rest and in transit


### Policies
- Enforce least-privilege access
- Require regular credential rotation
- Maintain tested incident response playbooks

### Monitoring
- Deploy SIEM and user behavior analytics
- Monitor east-west network traffic
- Alert on abnormal data access and exfiltration

### Architecture changes
- Adopt Zero Trust architecture
- Strongly segment internal networks
- Isolate identity and authentication infrastructure
- Protect cryptographic keys using centralized key management

### Awareness and training
- Conduct phishing awareness training
- Run regular security exercises
- Perform incident response simulations

### Zero Trust principles
- Never trust internal access by default
- Continuously verify users and devices
- Assume breach and limit blast radius
---

## Conclusion
The Yahoo 2013 data breach was the result of **multiple compounding security failures**, including weak identity controls, outdated cryptography, poor monitoring, and delayed detection. From a defender’s perspective, the incident demonstrates the importance of rapid response, strong access controls, and resilient security architecture.

Studying incidents like this helps defenders design systems that reduce risk, limit impact, and protect user trust.



# SolarWinds supply chain attack (2020)

The analysis focuses on **how a trusted software update mechanism was weaponized**, the weaknesses that enabled the attack, how defenders should respond after discovery, and what long-term controls are required to prevent similar incidents.

---

## 1. Brief Incident Overview

### What happened?
The SolarWinds supply chain attack involved the compromise of **SolarWinds’ Orion IT monitoring software build environment**. Attackers inserted malicious code into legitimate Orion software updates, which were digitally signed and distributed to customers between **March and June 2020**.

Once customers installed the compromised updates, the malware—later named **SUNBURST**—provided attackers with covert access to victim networks.

This attack is notable because it **exploited trust**, not software vulnerabilities in customer environments.

### Who was affected?
- Approximately **18,000 SolarWinds customers** installed the compromised update
- A smaller, high-value subset was actively exploited, including:
  - U.S. government agencies
  - Technology companies
  - Cybersecurity firms
  - Critical infrastructure organizations

### When did it occur?
- **Initial compromise of SolarWinds:** Likely late 2019
- **Malicious updates distributed:** March–June 2020
- **Attack discovered:** December 2020
- **Public disclosure:** December 2020

---

## 2. What Was Compromised

### Type of data and systems affected
The attack primarily compromised **enterprise infrastructure and identity systems**, not just data.

Affected assets included:
- Network monitoring servers (SolarWinds Orion)
- Domain controllers
- Identity providers (e.g., Active Directory, SAML)
- Email systems
- Cloud environments

In many cases, attackers obtained:
- Administrative credentials
- Access tokens
- Source code
- Email data
- Internal network visibility

### Scope of the damage
- Supply chain compromise at global scale
- Long dwell time (months of undetected access)
- Strategic espionage rather than mass data theft
- Severe impact on trust in software update mechanisms

The true scope remains partially unknown due to the stealthy nature of the campaign.

---

## 3. How the Attack Happened

### Initial attack vector
The attackers compromised SolarWinds’ **software build and update pipeline**.

Instead of attacking customers directly, they:
1. Gained access to SolarWinds’ development environment
2. Inserted malicious code into Orion software builds
3. Allowed SolarWinds to unknowingly distribute signed, trusted malware

This bypassed traditional security controls at customer organizations.

### Weaknesses that were exploited

1. **Insecure Software Build Pipeline**
   - Insufficient access controls in the build environment
   - Inadequate monitoring of build integrity
   - Lack of reproducible or verifiable builds

2. **Over-Trust in Digitally Signed Updates**
   - Customers trusted updates solely because they were signed
   - No secondary validation or behavioral inspection

3. **Lack of Supply Chain Risk Management**
   - Limited visibility into vendor security practices
   - Overreliance on third-party software without runtime controls

4. **Stealthy Malware Design**
   - SUNBURST remained dormant for weeks
   - Used legitimate protocols and low-noise communication
   - Blended in with normal Orion activity

5. **Weak Identity Monitoring**
   - Attackers targeted identity systems after initial access
   - Forged SAML tokens to access cloud services
   - Bypassed MFA by abusing trust relationships

6. **Insufficient East-West Monitoring**
   - Lateral movement within internal networks went undetected
   - No strong alerts for abnormal privilege escalation

---

## 4. Threat Elimination (Response)

This section focuses on **what should be done after discovering the breach**, not prevention.

### Containment actions
- Immediately disconnect SolarWinds Orion servers
- Block known command-and-control domains
- Revoke trust relationships with compromised systems
- Disable affected service accounts

### System isolation
- Isolate Orion servers from the network
- Assume identity systems are compromised
- Restrict administrative access across the environment

### Initial attack vector handling
Because the attack originated from a trusted update:
- Treat all affected software versions as compromised
- Validate integrity of all third-party software
- Identify downstream systems accessed by Orion

### Incident response steps

**Credential resets**
- Reset all credentials accessed by Orion
- Rotate service accounts, admin accounts, and API keys
- Reissue certificates and authentication tokens

**Patching and remediation**
- Remove compromised Orion versions
- Install clean, verified software
- Apply vendor and government-issued remediation guidance

**Malware removal**
- Hunt for persistence mechanisms
- Remove backdoors and secondary payloads
- Rebuild systems where compromise depth is unclear

**Forensics and coordination**
- Preserve logs and systems for investigation
- Engage national CERTs and law enforcement
- Coordinate with vendors and cloud providers

---

## 5. Threat Prevention (Future Protection)

This section focuses on **long-term security improvement**.

### Security controls
- Enforce strong access controls on build pipelines
- Implement runtime behavior monitoring for trusted software
- Apply least privilege to service accounts

### Policies
- Formal supply chain risk management policies
- Mandatory vendor security assessments
- Secure software development lifecycle (SSDLC) enforcement

### Monitoring
- Continuous monitoring of third-party software behavior
- Identity threat detection and response (ITDR)
- Alerts for abnormal token issuance and privilege escalation

### Architecture changes
- Zero Trust architecture across enterprise environments
- Segmentation of monitoring and management tools
- Harden identity infrastructure as crown-jewel assets

### Awareness and training
- Train teams on supply chain attack scenarios
- Regular tabletop exercises for vendor compromise
- Developer training on secure build practices

### Zero Trust principles
- Never assume trusted software is safe
- Continuously validate behavior, not identity alone
- Limit blast radius of management tools

---

## Conclusion
The SolarWinds attack fundamentally changed how defenders view **trust, software updates, and supply chain security**. It demonstrated that even well-secured organizations can be compromised through trusted vendors if behavioral monitoring, identity protection, and Zero Trust principles are not in place.
# WannaCry Ransomware Attack (2017) 
 
 **WannaCry ransomware attack of May 2017**, one of the most disruptive global cyber incidents to date. The attack demonstrated how unpatched vulnerabilities, weak asset management, and inadequate incident response readiness can lead to widespread operational impact.

This case study focuses on **how the attack spread, what was compromised, how defenders should respond after discovery, and how to prevent similar ransomware outbreaks in the future**.

---

## 1. Brief Incident Overview

### What happened?
WannaCry was a self-propagating ransomware attack that exploited a vulnerability in Microsoft Windows’ **SMBv1 protocol**. Once inside a network, the malware encrypted files and demanded a ransom payment in Bitcoin.

What made WannaCry especially damaging was its **worm-like behavior**, allowing it to spread automatically across vulnerable systems without user interaction.

### Who was affected?
- Over **230,000 systems** across more than **150 countries**
- Hospitals, government agencies, enterprises, and critical infrastructure
- Notable victims included:
  - UK National Health Service (NHS)
  - Telecommunications providers
  - Manufacturing and logistics companies

### When did it occur?
- **Initial outbreak:** May 12, 2017
- **Rapid global spread:** Within hours
- **Containment:** Following days after emergency mitigation efforts

---

## 2. What Was Compromised

### Type of data and systems affected
WannaCry primarily targeted **endpoint systems**, not centralized databases.

Compromised assets included:
- Windows workstations and servers
- File systems and shared network drives
- Business-critical applications running on affected hosts

The ransomware encrypted:
- Documents
- Databases
- Application files
- System data required for normal operations

### Scope of the damage
- Widespread operational disruption
- Service outages in healthcare and public services
- Financial losses due to downtime and recovery costs
- Limited confirmed ransom payments, but high indirect costs

The most severe impact was **availability**, not confidentiality.

---

## 3. How the Attack Happened

### Initial attack vector
WannaCry exploited **EternalBlue**, a vulnerability in SMBv1 disclosed after leaked nation-state tools became public.

The attack required:
- Exposed or internally reachable SMB services
- Unpatched Windows systems
- No user interaction

### Weaknesses that were exploited

1. **Unpatched Systems**
   - Microsoft had released a security patch months earlier
   - Many organizations failed to apply it
   - Legacy systems (e.g., Windows XP) were still in production

2. **Use of Legacy Protocols (SMBv1)**
   - SMBv1 was outdated and insecure
   - Enabled remote code execution
   - Often unnecessary but still enabled

3. **Flat Network Architecture**
   - Poor network segmentation
   - Allowed rapid lateral movement
   - No internal containment once infected

4. **Lack of Endpoint Security Controls**
   - Insufficient malware detection
   - No exploit prevention mechanisms
   - Limited behavioral monitoring

5. **Inadequate Asset Visibility**
   - Organizations did not know which systems were vulnerable
   - Poor inventory of operating systems and patch levels

---

## 4. Threat Elimination (Response)

This section focuses on **what should be done immediately after discovering a WannaCry-style ransomware infection**.

### Containment actions
- Disconnect infected systems from the network
- Block SMB traffic (TCP port 445) at network boundaries
- Disable SMBv1 across the environment
- Prevent further lateral movement

### System isolation
- Quarantine infected endpoints
- Assume adjacent systems may be compromised
- Isolate critical servers from affected segments

### Initial attack vector handling
Because the attack exploited a known vulnerability:
- Identify all unpatched systems
- Prioritize high-risk and internet-facing assets
- Apply emergency patches

### Incident response steps

**Credential and access review**
- Audit for unauthorized privilege escalation
- Reset credentials used on infected systems
- Review service accounts for misuse

**Patching**
- Apply Microsoft security updates immediately
- Install out-of-band patches for unsupported systems
- Remove or disable vulnerable protocols

**Malware removal**
- Wipe and rebuild infected systems
- Restore data from clean backups
- Verify system integrity before reconnecting

**Operational recovery**
- Validate backups before restoration
- Prioritize critical services
- Communicate clearly with stakeholders

---

## 5. Threat Prevention (Future Protection)

This section focuses on **long-term security improvement**.

### Security controls
- Automated patch management
- Endpoint detection and response (EDR)
- Network-based intrusion prevention
- Application allowlisting

### Policies
- Formal vulnerability management program
- Defined patch SLAs based on risk
- Legacy system decommissioning policy

### Monitoring
- Continuous vulnerability scanning
- Alerts for exploit attempts on known CVEs
- Monitoring for lateral movement activity

### Architecture changes
- Strong network segmentation
- Zero Trust principles for internal traffic
- Restrict administrative access paths
- Isolate legacy systems

### Awareness and training
- Incident response drills for ransomware scenarios
- IT staff training on emergency patching
- Executive tabletop exercises focused on availability impact

### Zero Trust principles
- Never assume internal systems are safe
- Limit east-west communication
- Continuously validate device health
- Reduce blast radius of compromised hosts

---

## Conclusion
The WannaCry ransomware attack was not a zero-day failure but a **failure of basic cyber hygiene at scale**. The incident demonstrated how delayed patching, legacy systems, and flat networks can rapidly turn a known vulnerability into a global crisis.

For defenders, WannaCry reinforces a critical lesson:
> *Availability is a security objective — and patching is non-negotiable.





