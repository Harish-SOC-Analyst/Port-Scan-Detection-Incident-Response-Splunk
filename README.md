# SOC-Port-Scan-Detection-Incident-Response-Splunk
Port scan detection and incident response using Splunk SIEM with Windows Firewall logs and Nmap attack simulation.

Title -
Port Scan Detection using Splunk SIEM

Objective -
Detect and investigate possible port scanning activity from a Kali Linux attacker machine against a Windows target machine using Windows Firewall logs in Splunk.

Lab Setup -
Kali Linux VM (attacker) Windows VM with UF (target) Main Host (SIEM server Splunk)

Incident Summary -
Attack Type: Port Scan / Network Service Discovery   
Source IP: 192.168.56.102 (Kali attacker VM)  
Target IP: 192.168.56.101 (Windows victim VM)  
Unique Destination Ports Detected: 16  
Observed Ports: 123, 135, 137, 138, 139, 1900, 445, 49664, 49665, 49666, 49667, 49668, 49669, 5040, 5355, 7680  
Detection Source: Windows Firewall logs ingested into Splunk  
Incident Status: True Positive - Authorized Lab Simulation
Severity: Medium

Reason:
No exploitation or successful compromise was identified. Activity was limited to reconnaissance.


Detection Logic (SPL) -
index=firewall
| stats dc(dest_port) as dest_ports values(dest_port) by src_ip 
| where dest_ports > 10
| sort -dest_ports

Detection Condition:
Single source IP communicating with more than 10 unique destination ports.

Triage -
Confirmed source IP 192.168.56.102 as Kali attacker machine.
Verified target IP 192.168.56.101 as Windows victim machine.
Observed multiple destination ports contacted from the same source IP.
Reviewed Windows Firewall logs in Splunk.
Classified the activity as possible port scanning 

“The port scan alert was triaged and classified as a medium-severity incident based on multiple destination ports contacted by a single source IP within the lab environment.”

MITRE ATT&CK -
T1046 – Network Service Discovery

Incident Response -

Validated the alert as a true positive.
Confirmed the activity was authorized lab testing.
Reviewed allowed and dropped firewall connections.
Checked for signs of follow-up exploitation or login attempts.
Recommended blocking the source IP if this activity is observed in production without authorization.
Escalation required if scanning is followed by brute force, exploitation, or lateral movement.

Conclusion -
Port scanning activity was successfully simulated using Nmap and detected in Splunk using Windows Firewall logs. The source IP 192.168.56.102 contacted 16 unique destination ports on the Windows target machine, indicating network service discovery behavior. The incident was validated as a true positive authorized lab simulation.
