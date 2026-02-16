# attack_knowledge.py
# --------------------------------------------------
# Hybrid IDS Intrusion Knowledge Base
# Ensemble Learning + Signature-Based Analysis
# --------------------------------------------------

ATTACK_KNOWLEDGE = {

# ==================================================
# 1. BRUTE FORCE & CREDENTIAL ATTACKS
# ==================================================

"FTP-BruteForce": {
    "category": "Credential Attacks",
    "severity": "High",
    "description": (
        "An FTP Brute Force attack occurs when an attacker repeatedly attempts "
        "to authenticate against an FTP service using multiple username–password "
        "combinations. These attacks are usually automated and exploit weak, "
        "default, or reused credentials to gain unauthorized access."
    ),
    "evidence": [
        "Abnormally high number of failed FTP login attempts",
        "Repeated authentication requests from the same source IP",
        "Authentication failure rate exceeding normal thresholds",
        "Hybrid IDS confirmation using ML anomaly scoring and FTP brute-force signatures"
    ],
    "root_cause": (
        "Weak or reused credentials combined with unrestricted exposure "
        "of the FTP service to external networks."
    ),
    "impact": [
        "Unauthorized system access",
        "Data compromise or exfiltration",
        "Malicious file upload via FTP",
        "Potential lateral movement within the network"
    ],
    "mitigation": [
        "Enforce strong password policies",
        "Implement account lockout and rate limiting",
        "Enable multi-factor authentication",
        "Restrict FTP access by IP allowlists",
        "Replace FTP with secure alternatives such as SFTP or FTPS"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

"SSH-BruteForce": {
    "category": "Credential Attacks",
    "severity": "High",
    "description": (
        "An SSH Brute Force attack involves repeated authentication attempts "
        "against SSH services to gain unauthorized remote access. Attackers "
        "exploit weak credentials and open SSH ports, often leading to full "
        "server compromise."
    ),
    "evidence": [
        "Multiple failed SSH login attempts",
        "Abnormal authentication frequency",
        "Repeated access attempts from identical or rotating IPs",
        "Machine learning detection of anomalous login behavior",
        "Signature-based SSH brute-force pattern match"
    ],
    "root_cause": (
        "Password-based SSH authentication with weak credentials "
        "and unrestricted network exposure."
    ),
    "impact": [
        "Unauthorized remote access",
        "Privilege escalation",
        "Malware installation",
        "Use of compromised host for further attacks"
    ],
    "mitigation": [
        "Disable password-based SSH authentication",
        "Enforce key-based authentication",
        "Deploy intrusion prevention tools such as Fail2Ban",
        "Restrict SSH access using firewall rules and IP whitelisting"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

"Credential-Stuffing": {
    "category": "Credential Attacks",
    "severity": "High",
    "description": (
        "Credential Stuffing attacks use leaked or breached username–password "
        "pairs to attempt authentication across multiple services. These attacks "
        "rely heavily on password reuse and automated login attempts."
    ),
    "evidence": [
        "Login attempts across many user accounts",
        "Authentication patterns matching known breached credentials",
        "Anomalous success-to-failure ratios detected by ML model"
    ],
    "root_cause": (
        "Password reuse across platforms and lack of multi-factor authentication."
    ),
    "impact": [
        "Account compromise",
        "Identity theft",
        "Unauthorized access to sensitive systems"
    ],
    "mitigation": [
        "Enforce multi-factor authentication",
        "Monitor for breached credentials",
        "Implement login anomaly detection",
        "Educate users on password hygiene"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

# ==================================================
# 2. DENIAL OF SERVICE (DoS)
# ==================================================

"DoS-SYN-Flood": {
    "category": "Denial of Service",
    "severity": "High",
    "description": (
        "A SYN Flood attack overwhelms a target server by sending a large volume "
        "of TCP SYN packets without completing the handshake, exhausting server "
        "resources and preventing legitimate connections."
    ),
    "evidence": [
        "Extremely high rate of TCP SYN packets",
        "Large number of half-open TCP connections",
        "Traffic volume anomalies detected by ML",
        "Signature match for SYN flood attack patterns"
    ],
    "root_cause": (
        "Lack of SYN rate limiting and insufficient network hardening."
    ),
    "impact": [
        "Service unavailability",
        "Network resource exhaustion"
    ],
    "mitigation": [
        "Enable SYN cookies",
        "Apply firewall-based rate limiting",
        "Deploy intrusion prevention systems"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

"DoS-HTTP-Flood": {
    "category": "Denial of Service",
    "severity": "High",
    "description": (
        "An HTTP Flood attack overwhelms web servers by sending a massive number "
        "of HTTP requests, often designed to resemble legitimate traffic to evade "
        "basic detection mechanisms."
    ),
    "evidence": [
        "High HTTP request rate per second",
        "Repeated identical GET or POST requests",
        "Abnormal session behavior detected by ML"
    ],
    "root_cause": (
        "Unprotected web endpoints and lack of application-layer rate controls."
    ),
    "impact": [
        "Application downtime",
        "Degraded user experience"
    ],
    "mitigation": [
        "Deploy Web Application Firewalls (WAF)",
        "Implement application-level rate limiting",
        "Use traffic profiling and anomaly detection"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

# ==================================================
# 3. DISTRIBUTED DENIAL OF SERVICE (DDoS)
# ==================================================

"DDoS-UDP-Amplification": {
    "category": "Distributed Denial of Service",
    "severity": "Critical",
    "description": (
        "A UDP Amplification attack leverages misconfigured UDP services to "
        "amplify traffic volume, flooding the target network using spoofed "
        "source addresses."
    ),
    "evidence": [
        "Large inbound UDP response packets",
        "Multiple geographically distributed source IPs",
        "Traffic amplification ratios detected by ML"
    ],
    "root_cause": (
        "Open UDP services exploited as amplification vectors."
    ),
    "impact": [
        "Severe network congestion",
        "Complete service outage"
    ],
    "mitigation": [
        "ISP-level traffic filtering",
        "DDoS mitigation services",
        "Disable unnecessary UDP services"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

# ==================================================
# 4. WEB APPLICATION ATTACKS
# ==================================================

"SQL-Injection": {
    "category": "Web Attacks",
    "severity": "Critical",
    "description": (
        "SQL Injection attacks inject malicious SQL statements into application "
        "inputs, allowing attackers to manipulate backend databases and extract "
        "or modify sensitive data."
    ),
    "evidence": [
        "Suspicious SQL keywords in request payloads",
        "Database error responses",
        "Signature match for known SQL injection patterns"
    ],
    "root_cause": (
        "Lack of input validation and improper query construction."
    ),
    "impact": [
        "Database compromise",
        "Data leakage or manipulation"
    ],
    "mitigation": [
        "Use prepared statements",
        "Sanitize all user inputs",
        "Deploy Web Application Firewall rules"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

"XSS": {
    "category": "Web Attacks",
    "severity": "High",
    "description": (
        "Cross-Site Scripting attacks inject malicious scripts into web pages, "
        "allowing attackers to hijack user sessions or perform actions on behalf "
        "of authenticated users."
    ),
    "evidence": [
        "Script tags detected in request payloads",
        "Unescaped output patterns",
        "Signature match for XSS attack vectors"
    ],
    "root_cause": (
        "Improper output encoding and lack of content validation."
    ),
    "impact": [
        "Session hijacking",
        "User data theft"
    ],
    "mitigation": [
        "Output encoding",
        "Implement Content Security Policy (CSP)",
        "Validate and sanitize user inputs"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

# ==================================================
# 5. RECONNAISSANCE & SCANNING
# ==================================================

"Port-Scanning": {
    "category": "Reconnaissance",
    "severity": "Medium",
    "description": (
        "Port scanning involves systematically probing network ports to identify "
        "active services and potential vulnerabilities."
    ),
    "evidence": [
        "Sequential or randomized port connection attempts",
        "Unusual connection patterns detected by ML"
    ],
    "root_cause": (
        "Exposed network services and insufficient firewall restrictions."
    ),
    "impact": [
        "Attack surface discovery",
        "Preparation for subsequent attacks"
    ],
    "mitigation": [
        "Firewall rules",
        "Port hardening",
        "Network segmentation"
    ],
    "final_verdict": "Suspicious — Confirmed by Hybrid Detection Engine"
},

# ==================================================
# 6. MALWARE & BOTNET ACTIVITY
# ==================================================

"C2-Traffic": {
    "category": "Malware",
    "severity": "Critical",
    "description": (
        "Command and Control (C2) traffic indicates communication between an "
        "infected host and attacker-controlled servers, enabling remote control "
        "and data exfiltration."
    ),
    "evidence": [
        "Periodic beaconing behavior",
        "Connections to known malicious IP addresses",
        "ML-detected abnormal traffic patterns"
    ],
    "root_cause": (
        "Malware infection within the network."
    ),
    "impact": [
        "Remote system control",
        "Data exfiltration",
        "Botnet participation"
    ],
    "mitigation": [
        "Endpoint protection solutions",
        "Network isolation of infected hosts",
        "Threat intelligence-based blocking"
    ],
    "final_verdict": "Malicious — Confirmed by Hybrid Detection Engine"
},

# ==================================================
# 7. BENIGN TRAFFIC
# ==================================================

"Benign": {
    "category": "Normal",
    "severity": "None",
    "description": (
        "Legitimate network traffic generated by normal user activity without "
        "any malicious intent."
    ),
    "evidence": [],
    "root_cause": "",
    "impact": [],
    "mitigation": [],
    "final_verdict": "Benign — No Threat Detected"
}

}
