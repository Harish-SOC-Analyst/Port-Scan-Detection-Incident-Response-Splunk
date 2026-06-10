# Security Incident Report: Port Scan Detection

## Incident Overview

Incident Name: Possible Port Scanning Activity Detected

Severity: Medium

Status: Closed - True Positive (Authorized Security Testing)

Detection Source: Splunk SIEM

Log Source: Windows Defender Firewall Logs

Attack Type: Network Reconnaissance / Port Scan


## Alert Details

A suspicious network scanning activity was detected where a single source IP attempted communication with multiple destination ports on a Windows endpoint.

The activity was identified using Splunk analysis by counting unique destination ports contacted by each source IP.


## Affected Assets

Attacker IP:
192.168.56.102

Hostname:
Kali Linux VM

Target IP:
192.168.56.101

Asset:
Windows Endpoint


## Detection Query

```spl
index=firewall
| stats dc(dest_port) as dest_ports values(dest_port) by src_ip 
| where dest_ports > 10
| sort -dest_ports


```

## Investigation Findings

During investigation, source IP 192.168.56.102 was identified as the highest suspicious source.

The host attempted communication with multiple destination ports on the Windows endpoint.

Total Unique Destination Ports Detected:

16

Observed Destination Ports:

123  
135  
137  
138  
139  
1900  
445  
49664  
49665  
49666  
49667  
49668  
49669  
5040  
5355  
7680


Important Windows services identified:

135 - RPC Endpoint Mapper

139 - NetBIOS Session Service

445 - SMB File Sharing


The behavior indicates possible network reconnaissance activity before exploitation.


## MITRE ATT&CK Mapping

Tactic:
Discovery

Technique:
Network Service Discovery

Technique ID:
T1046



## SOC Analyst Triage

Alert Status:
True Positive

Severity:
Medium

Reason:

Multiple destination ports were accessed by a single source IP, indicating possible reconnaissance activity.

Business Impact:

No compromise identified. Activity was limited to network discovery.


## Incident Response Actions

- Validated source and destination IP addresses.
- Reviewed firewall events in Splunk.
- Confirmed scanning behavior.
- Checked for further suspicious activity.
- Documented incident findings.

Production Recommendations:

- Block unauthorized scanning sources.
- Investigate endpoint activity after port scans.
- Monitor authentication attempts following reconnaissance.
- Tune SIEM alerts for port scan detection.


## Final Classification

True Positive - Authorized Security Lab Simulation
