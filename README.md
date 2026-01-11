<p align="center">
  <img src="screenshots/analysis-banner.png" width="750">
</p>

# Network Traffic Analysis Report
<p align="center">
  <img src="https://img.shields.io/badge/SOC-Traffic%20Monitoring-blue">
  <img src="https://img.shields.io/badge/Wireshark-Packet%20Analysis-green">
  <img src="https://img.shields.io/badge/Attack%20Simulation-Nmap%20%7C%20Hydra-red">
</p>

## 1. Executive Summary

This report documents the capture and analysis of network traffic within a controlled lab environment to identify normal behavior and malicious activity from a Security Operations Center (SOC) perspective.

The analysis focused on:
- Baseline network behavior
- Port scanning reconnaissance
- SSH brute-force attack patterns

All findings were validated using packet-level inspection in Wireshark.


## 2. Lab Environment

| Component | Details |
|--------|--------|
| Attacker | Kali Linux |
| Victim | Ubuntu Linux |
| Monitoring Tool | Wireshark |
| Virtualization | VMware Workstation (NAT) |


## 3. Methodology

The investigation followed a standard SOC workflow:

1. Establish baseline (normal traffic)
2. Introduce suspicious activity
3. Capture traffic
4. Analyze packets
5. Identify indicators of compromise (IOCs)
6. Document findings and mitigations


## 4. Baseline Traffic Analysis

<p align="center">
  <img src="screenshots/normal-traffic.png" width="800">
</p>

### Observed Traffic
- ICMP echo requests (ping)
- Standard TCP handshakes
- Low packet volume

### Assessment
This traffic represents legitimate communication with no indicators of malicious intent.


## 5. Port Scanning Analysis

<p align="center">
  <img src="screenshots/port-scan-wireshark.png" width="800">
</p>

### Attack Description
A TCP SYN scan was executed from the attacker machine to enumerate open services on the target system.

### Assessment
The traffic pattern clearly indicates reconnaissance activity commonly performed prior to exploitation.

## 6. Open Port Identification (SSH)

<p align="center">
  <img src="screenshots/syn-ack-port22.png" width="800">
</p>

### Findings
- Port 22 responded with SYN-ACK packets
- Confirms SSH service was actively listening

### Security Implication
Open management ports significantly increase attack surface if not properly secured.

## 7. SSH Brute-Force Attack Analysis

<p align="center">
  <img src="screenshots/ssh-bruteforce.png" width="800">
</p>

### Attack Description
A brute-force login attempt was simulated against the SSH service.

### Indicators Observed
- Repeated authentication attempts
- High-frequency SSH packets
- Single source IP targeting port 22
- Short time interval between attempts

### Wireshark Filter Used
tcp.flags.syn == 1 && tcp.flags.ack == 0

### Indicators Observed
- Multiple SYN packets from a single source
- Sequential destination port probing
- Absence of completed TCP sessions

### Assessment
This activity strongly indicates a brute-force attack attempting to gain unauthorized access.

## 8. Impact Assessment

If successful, this attack could result in:
- Unauthorized system access
- Privilege escalation
- Lateral movement within a network


## 9. Mitigation Recommendations

- Disable password-based SSH authentication
- Enforce SSH key-based authentication
- Implement rate-limiting tools (e.g., fail2ban)
- Restrict SSH access via firewall rules
- Continuous network traffic monitoring


## 10. Conclusion

This lab demonstrates the effectiveness of packet-level analysis in detecting early-stage and active attacks. The techniques used align with real-world SOC monitoring and incident investigation practices.

## 11. Disclaimer

All activities were conducted in a controlled lab environment for educational purposes only.
