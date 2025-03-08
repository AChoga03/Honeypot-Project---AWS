# Honeypot Intrusion Detection Project --> with AWS & T-pot

## Overview
This project uses a honeypot setup on an AWS EC2 instance to capture and analyze network attacks, leveraging T-Pot, an open-source honeypot framework. T-Pot collects data from various emulated services like Dionaea, Cowrie, and Suricata, visualized through Kibana. The goal is to observe attack patterns, analyze attacker behaviors, and identify common vulnerabilities.

## Project Objectives
- Deploy honeypots on AWS to simulate vulnerable services.
- Capture data on attack attempts, including IP addresses, protocols, and attack vectors.
- Use visualization and analysis tools to interpret and report on attacker behaviors.
- Provide recommendations to improve security based on observed attack patterns.

## What is a Honeypot
- A honeypot is a security tool that mimics a vulnerable system or network to attract cyber attackers, allowing security teams to observe and analyze malicious behavior without risking real assets. By capturing data on attack methods, source IPs, and attempted exploits, honeypots provide valuable insights into threat tactics and can help improve overall security defenses. They are often used in cybersecurity research, threat detection, and intrusion detection systems.

## Setup Instructions

### 1. AWS & T-pot Setup
1. **Instance Configuration**: Launch an EC2 instance in your AWS account.
   - OS image type: Ubuntu.
   - Recommended instance type: `t2.medium` or higher.
   - Keypair: Create new Keypair(use configs in [image](https://github.com/user-attachments/assets/a4145240-f91e-451f-94e0-a7549960a259). Remember where it is Downloaded to.
).
   - Network Settings: Configure Network settings to Allow SSH traffic from Your IP Address (use configs in [image](https://github.com/user-attachments/assets/00a970c1-ad2e-4d6e-a8bb-9af41013a78c)
   - Configure Storage: Choose amount of storage you find necessary.
   - Now Launch the instance.


2. **Access via SSH**:
   - Now the instance is Created. You can find it on the instance page with the IP address, now just hit connect (view [image](https://github.com/user-attachments/assets/047f3b70-5060-4113-b5fa-deecdb98cf06)
)
   - Download the SSH key file (e.g., `Examplekey.pem`) and set permissions: `chmod 400 Examplekey.pem`.
   - Connect to the instance:
     ```bash
     ssh -i "Examplekey.pem" ubuntu@<your-ec2-instance-ip>
     ```

3. **Install T-Pot**:
   - **Clone the T-Pot Repository**:
     ```bash
     git clone https://github.com/telekom-security/tpotce
     ```
   - **Navigate to the T-Pot Folder**:
     ```bash
     cd tpotce
     ```
   - **Run the Installer**:
     Execute the installer script as a non-root user:
     ```bash
     ./install.sh
     ```

     ⚠️ The installer will:
     - Change the SSH port to `tcp/64295`.
     - Disable the DNS Stub Listener to avoid port conflicts.
     - Set **SELinux** to Monitor Mode.
     - Set the firewall target for the public zone to **ACCEPT**.
     - Install Docker, recommended packages, and remove conflicting packages.
     - Add the current user to the **docker** group.
     - Add helpful aliases for Docker commands and file navigation.
     - Display open ports on the host and compare with T-Pot's required ports.
     - Add and enable `tpot.service` to automatically start T-Pot on boot.

   - **Follow Installer Instructions**:
     - You will need to enter your password (sudo or root) at least once during installation.
     - Check for any error messages or port conflicts that might require adjustment.

4. **Reboot the System**:
   - After installation, reboot the instance:
     ```bash
     sudo reboot
     ```

After rebooting, T-Pot should be fully installed and configured on your EC2 instance.

For more detailed installation instructions and configurations, refer to the official [T-Pot GitHub repository](https://github.com/telekom-security/tpotce?tab=readme-ov-file#get-and-install-t-pot).

5. **Security & Firewall configuration**:
   - Now navigate to Security Groups and Edit Inbound Rules then set these parameters.
   
   ![image](https://github.com/user-attachments/assets/432c8dd8-0e25-4d57-bfa6-e64d07f8abe3)

6. **Access T-pot website**:
   - Next get to the T-pot website via port 64297 (https://ip-address:64297), use same IP address on Instance page.
   - Now sign in using the username and password from the T-pot installation process (view [image](https://github.com/user-attachments/assets/bca288d2-d245-463a-9aa6-75daa84dbe41)).
     
### 2. T-Pot Use
- **Introduction**: T-Pot is an all-in-one honeypot platform that runs multiple honeypots in Docker containers. It captures attacks on common protocols and provides a Kibana dashboard for data visualization.
- **Services & Modules**: 
  - **Dionaea**: Emulates vulnerabilities for capturing malware.
  - **Cowrie**: Mimics SSH/Telnet servers to log attacker interactions.
  - **Suricata**: An intrusion detection system capturing network threats.
  - etc...
 
![tpot-home](https://github.com/user-attachments/assets/9e1ed22d-d00b-40ca-8d7f-f6432162e9cb)

### 3. Data Visualization with Kibana
- **Dashboard & Data Visualization**: Kibana interfaces with T-Pot to provide real-time visualizations of honeypot logs. You can see attack origins, methods, and trends over time.
- **Queries & Alerts**: Set up queries for common attack sources, protocols, and frequencies, and configure alerts for repeated brute-force attempts or other suspicious activities.

### 4. Analysis Tools
- **CyberChef**: Analyze data transformations, including decoding payloads or viewing suspicious file contents.
- **Elasticvue**: Manage and query Elasticsearch indices for deeper data insights.
- **Spiderfoot**: Perform reconnaissance on attacker IPs to gather context on potential threats.

## Data Analysis

### Attack Map

1. **Recent Attack Volume**
   - **Hourly Attacks**: 185 attempts recorded in the last hour.
   - **Daily Attacks**: 29,252 attempts recorded over the last 24 hours, indicating high attack frequency and sustained probing activity.
   
2. **Top Attack Origin**
   - **Primary Source**: The highest number of attacks (3,033) originated from **Germany**, suggesting a significant volume of malicious traffic from this region.
   
   - **Insight**: The high attack frequency from Germany may indicate concentrated botnet activity or automated scans originating from this region. Applying geo-blocking or monitoring German IP addresses closely may help in mitigating potential threats.
  
![Attack map](https://github.com/user-attachments/assets/dd36107f-80c1-42b3-a03c-0f9c46336039)


### T-Pot Dashboard

1. **Attack Focus (Dionaea & Heralding)**
   - **Dionaea** captures malware by emulating common vulnerabilities, making it attractive to attackers focused on deploying exploits.
   - **Heralding** simulates authentication protocols, attracting credential-based attacks like brute-forcing.
   - **Insight**: Attackers prioritize targeting malware-susceptible platforms (Dionaea) and weak-authentication services (Heralding) over HTTP-based targets like Glastopf.

2. **Attack Timeline**
   - Observations show **peaks in attack activity**, suggesting botnet-driven mass scans, likely in response to new exploit campaigns.

3. **Port Targeting**
   - **Port 22 (SSH)** is frequently targeted for brute-force attacks, while **Ports 80 (HTTP)**, **443 (HTTPS)**, and **445 (SMB)** are targeted for web and network file-sharing exploits.
   - **Insight**: Strong access controls and enhanced SSH security measures on critical ports are essential to mitigate these attacks.

4. **Geolocation & IP Reputation**
   - High attack activity originates from **North America, Europe, and Asia**, regions known for botnet hubs. Frequent attacks from countries like the U.S. suggest implementing geo-blocking for high-risk regions may be beneficial.

5. **OS Targeting**
   - **Linux systems** are more frequently targeted, reflecting attackers’ preference for environments commonly used in server applications.

6. **Common Credentials**
   - Attackers frequently attempt to access the system using **default or simple credentials** (e.g., `admin`, `root`).
   - **Recommendation**: Enforce strong, complex passwords and multi-factor authentication (MFA) on critical access points to prevent unauthorized access.

![T-Pot Dashboard](https://github.com/user-attachments/assets/34a7b3af-5026-4e4e-996b-b403d5d4b64a)<br/>
![T-Pot Dashboard2](https://github.com/user-attachments/assets/e9723bbf-8d92-4417-ab93-0a16831098c8)<br/>


### Cowrie Dashboard
### Cowrie Dashboard Analysis

1. **Attack Frequency and Source**
   - **Total Attacks**: 582 attacks were recorded over the monitored period, originating from 144 unique IP addresses.
   - **Top Attack Sources**: Significant attack traffic came from **China, India, Taiwan, the United States, and Russia**.
   
2. **Service Targeting**
   - **Protocol Breakdown**: The main targets were **SSH** and **Telnet** services, with Telnet experiencing slightly higher engagement.
   - **Insight**: This suggests attackers aim to gain shell access, often using weak credentials to establish persistent connections.

3. **Username and Password Analysis**
   - **Common Usernames**: Default usernames like `root`, `admin`, `oracle`, and `ubuntu` were frequently targeted, indicating they are typical entry points in credential-stuffing attacks.
   - **Password Trends**: Commonly used passwords include weak combinations like `123456`, `admin123`, and `password`, highlighting attackers' reliance on easily guessable passwords.
   - **Insight**: The prevalence of weak or default credentials in attacks highlights the need for strict access control measures, such as enforcing strong password policies and disabling default accounts.

4. **Command Line Input Patterns**
   - **Typical Commands**: Attackers often probe system information using commands like `uname -a` and `cat /proc/cpuinfo`, attempt to access sensitive files, and try to establish backdoors.
   - **Insight**: These commands suggest attackers are interested in understanding system architecture and vulnerabilities, potentially customizing their malware or exploit tools based on the environment.

![Cowrie Dashboard](https://github.com/user-attachments/assets/3c86425a-4fbb-470f-bced-0d8bb92f7494)<br/>
![Cowrie Dashboard2](https://github.com/user-attachments/assets/d5681699-9a34-43a3-924a-b274702c2b92)<br/>

### Furthur Analysis Video Tutorial

I created a video that demonstrates how to:
- Perform further analysis on the **Cowrie** and **Suricata** dashboards.
- Use **CyberChef** for data analysis.
- Conduct an **SSH attack** on the honeypot using **Hydra** on Kali Linux.

 [👉Video Tutorial Here](https://youtu.be/IEQkkmymamc?si=74XcGGnmzZgnEF4j)

## Insights & Security Recommendations
- Based on observed attack patterns:
  - **Disable unused ports** and limit access to critical services.
  - **Enable multi-factor authentication (MFA)** for SSH access.
  - Conduct **regular log reviews** to detect unusual access attempts.

## Future Enhancements
- Deploy additional honeypot types for a broader attack surface.
- Automate alerting and reporting for higher-priority incidents.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
