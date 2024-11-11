# Honeypot Intrusion Detection Project - with AWS & T-pot

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

### 1. AWS Setup
1. **Instance Configuration**: Launch an EC2 instance in your AWS account.
   - OS image type: Ubuntu.
   - Recommended instance type: `t2.medium` or higher.
   - Keypair: Create new Keypair(use configs in [image](./images/keypair-configs.svg)
).
   - Security Group: Configure to allow inbound traffic on specific honeypot ports (e.g., 22, 80, 445) while restricting access to other critical services.

2. **Access via SSH**:
   - Download the SSH key file (e.g., `Examplekey.pem`) and set permissions: `chmod 400 Examplekey.pem`.
   - Connect to the instance:
     ```bash
     ssh -i "Examplekey.pem" ubuntu@<your-ec2-instance-ip>
     ```

### 2. T-Pot Setup
- **Introduction**: T-Pot is an all-in-one honeypot platform that runs multiple honeypots in Docker containers. It captures attacks on common protocols and provides a Kibana dashboard for data visualization.
- **Services & Modules**: 
  - **Dionaea**: Emulates vulnerabilities for capturing malware.
  - **Cowrie**: Mimics SSH/Telnet servers to log attacker interactions.
  - **Suricata**: An intrusion detection system capturing network threats.
 
![tpot-home](https://github.com/user-attachments/assets/b6962807-529b-4c4e-9f4a-eb297e1d57bf)



![T-Pot Dashboard](./images/tpot-dashboard.svg = 400x400)

### 3. Data Visualization with Kibana
- **Dashboard & Data Visualization**: Kibana interfaces with T-Pot to provide real-time visualizations of honeypot logs. You can see attack origins, methods, and trends over time.
- **Queries & Alerts**: Set up queries for common attack sources, protocols, and frequencies, and configure alerts for repeated brute-force attempts or other suspicious activities.

![Kibana Dashboard](./images/kibana-dashboard.png)

### 4. Analysis Tools
- **CyberChef**: Analyze data transformations, including decoding payloads or viewing suspicious file contents.
- **Elasticvue**: Manage and query Elasticsearch indices for deeper data insights.
- **Spiderfoot**: Perform reconnaissance on attacker IPs to gather context on potential threats.

## Data Analysis

### T-Pot Dashboard
- **Attack Frequency & Distribution**: Visualizes daily/weekly attack patterns and highlights peak attack times.
- **Top Attack Sources**: Shows common IPs and geolocations of attackers.
- **Targeted Ports & Protocols**: Identifies frequently targeted services and infers attacker goals.

![Attack Map](./images/attack-map.png)

### Cowrie Dashboard
- **Brute Force Attempts**: Captures attempted login credentials to analyze common brute-force tactics.
- **Command Execution**: Logs commands entered by attackers, providing insights into their intent (e.g., file downloads, backdoor installation).

![Cowrie Dashboard](./images/cowrie-dashboard.png)

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
