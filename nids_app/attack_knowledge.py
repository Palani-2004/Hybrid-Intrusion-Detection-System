# attack_knowledge.py
# --------------------------------------------------
# Hybrid IDS Intrusion Knowledge Base
# Ensemble Learning + Signature-Based Detection
# --------------------------------------------------

ATTACK_KNOWLEDGE = {

# ==================================================
# 1. NETWORK FLOODING / AVAILABILITY ATTACKS
# ==================================================

"Data Flood": {
    "category": "Availability Attacks",
    "severity": "High",
    "description": (
        "A Data Flood attack overwhelms a network or server by transmitting "
        "extremely large volumes of packets within a short time period. "
        "The objective is to exhaust bandwidth and system processing resources "
        "so legitimate traffic cannot be served."
    ),
    "technical_details": (
        "Attackers generate massive packet streams using automated tools or "
        "botnets. These packets saturate network interfaces, buffers, and "
        "processing queues."
    ),
    "evidence": [
        "Extremely high packet transmission rate",
        "Network congestion and latency spikes",
        "Large volumes of repetitive packets",
        "Unusual increase in inbound traffic",
        "Packet drop rate significantly increased"
    ],
    "root_cause": (
        "Lack of traffic filtering, inadequate bandwidth control, and "
        "absence of rate-limiting mechanisms."
    ),
    "impact": [
        "Network congestion",
        "Service disruption",
        "Packet loss",
        "Infrastructure resource exhaustion"
    ],
    "mitigation": [
        "Implement traffic shaping and rate limiting",
        "Deploy network intrusion detection systems",
        "Configure firewall filtering rules",
        "Increase network capacity"
    ],
    "real_world_example": (
        "Attackers use botnet nodes to continuously send packets to a "
        "target web server until the network interface becomes saturated."
    ),
    "final_verdict": "Malicious — Confirmed Flooding Activity"
},

"DoS": {
    "category": "Availability Attacks",
    "severity": "High",
    "description": (
        "A Denial of Service (DoS) attack attempts to disrupt the availability "
        "of a system or network by overwhelming it with excessive requests or "
        "traffic, preventing legitimate users from accessing services."
    ),
    "technical_details": (
        "DoS attacks typically target server resources such as CPU, memory, "
        "connection queues, or bandwidth using protocol or application-level "
        "flooding techniques."
    ),
    "evidence": [
        "Abnormally high traffic volume",
        "Sudden spike in packets per second",
        "High bandwidth utilization",
        "Repeated identical requests from same IP"
    ],
    "root_cause": (
        "Insufficient rate limiting and lack of defensive infrastructure."
    ),
    "impact": [
        "Service downtime",
        "Server crash",
        "Performance degradation"
    ],
    "mitigation": [
        "Implement request rate limiting",
        "Deploy Web Application Firewall",
        "Use DDoS mitigation services"
    ],
    "real_world_example": (
        "A malicious script repeatedly sends requests to a web server until "
        "its request queue becomes exhausted."
    ),
    "final_verdict": "Malicious — Confirmed DoS Activity"
},

"DoS-SYN-Flood": {
    "category": "Availability Attacks",
    "severity": "High",
    "description": (
        "A SYN Flood attack exploits the TCP handshake mechanism by sending "
        "large numbers of SYN packets without completing the handshake."
    ),
    "technical_details": (
        "The server allocates resources for half-open TCP connections, which "
        "eventually exhaust connection queues."
    ),
    "evidence": [
        "Large number of half-open TCP connections",
        "High SYN packet rate",
        "Incomplete TCP handshakes"
    ],
    "root_cause": "Lack of SYN rate limiting or SYN cookie protection.",
    "impact": [
        "Server resource exhaustion",
        "Connection queue overflow"
    ],
    "mitigation": [
        "Enable SYN cookies",
        "Deploy firewall rate limiting"
    ],
    "real_world_example": (
        "Attackers send thousands of SYN packets per second but never "
        "complete the handshake."
    ),
    "final_verdict": "Malicious — SYN Flood Detected"
},

"DoS-HTTP-Flood": {
    "category": "Availability Attacks",
    "severity": "High",
    "description": (
        "HTTP Flood attacks overwhelm web servers with large numbers of "
        "HTTP requests, exhausting application resources."
    ),
    "technical_details": (
        "Attackers send high volumes of GET or POST requests, often using "
        "distributed systems or botnets."
    ),
    "evidence": [
        "High rate of HTTP requests",
        "Repeated identical HTTP queries"
    ],
    "root_cause": "Unprotected web endpoints and lack of request throttling.",
    "impact": [
        "Application downtime",
        "Slow response times"
    ],
    "mitigation": [
        "Deploy WAF",
        "Enable API rate limiting"
    ],
    "real_world_example": (
        "Bots continuously request large dynamic pages causing CPU spikes."
    ),
    "final_verdict": "Malicious — HTTP Flood Detected"
},

# ==================================================
# 2. DATA BREACH / CONFIDENTIALITY ATTACKS
# ==================================================

"Data Exfiltration": {
    "category": "Data Breach",
    "severity": "Critical",
    "description": (
        "Data exfiltration is the unauthorized transfer of sensitive data "
        "from internal systems to external locations controlled by attackers."
    ),
    "technical_details": (
        "Attackers often use encrypted channels, DNS tunneling, or covert "
        "file transfers to move stolen data."
    ),
    "evidence": [
        "Large outbound data transfers",
        "Connections to unknown external IPs",
        "Encrypted outbound traffic spikes"
    ],
    "root_cause": "Compromised credentials or malware infection.",
    "impact": [
        "Sensitive data loss",
        "Regulatory penalties",
        "Reputational damage"
    ],
    "mitigation": [
        "Deploy Data Loss Prevention systems",
        "Monitor outbound traffic",
        "Implement strong access controls"
    ],
    "real_world_example": (
        "A compromised employee account uploads confidential files "
        "to an external cloud storage service."
    ),
    "final_verdict": "Malicious — Data Exfiltration Attempt"
},

# ==================================================
# 3. CREDENTIAL ATTACKS
# ==================================================

"BruteForce": {
    "category": "Credential Attacks",
    "severity": "High",
    "description": (
        "A brute force attack attempts to guess passwords by repeatedly "
        "trying different combinations until correct credentials are found."
    ),
    "technical_details": (
        "Attack tools automate password attempts against authentication "
        "systems using large password dictionaries."
    ),
    "evidence": [
        "Multiple login failures",
        "Repeated authentication attempts",
        "High login failure ratio"
    ],
    "root_cause": "Weak passwords and missing account lockout policies.",
    "impact": [
        "Unauthorized access",
        "Account compromise"
    ],
    "mitigation": [
        "Enable account lockout policies",
        "Use MFA",
        "Monitor login attempts"
    ],
    "real_world_example": (
        "An attacker attempts thousands of login attempts against "
        "an admin portal."
    ),
    "final_verdict": "Malicious — Brute Force Attack"
},

"SSH-BruteForce": {
    "category": "Credential Attacks",
    "severity": "High",
    "description": (
        "SSH brute force attacks repeatedly attempt authentication against "
        "SSH services to gain remote access."
    ),
    "technical_details": (
        "Automated scripts attempt thousands of username/password combinations."
    ),
    "evidence": [
        "Repeated SSH login failures",
        "Authentication attempts from same IP"
    ],
    "root_cause": "Weak SSH credentials.",
    "impact": [
        "Unauthorized remote access",
        "System compromise"
    ],
    "mitigation": [
        "Disable password authentication",
        "Use SSH keys",
        "Deploy Fail2Ban"
    ],
    "real_world_example": (
        "Bots attempt login attempts against port 22 continuously."
    ),
    "final_verdict": "Malicious — SSH Brute Force"
},

# ==================================================
# 4. WEB APPLICATION ATTACKS
# ==================================================

"SQL-Injection": {
    "category": "Web Attacks",
    "severity": "Critical",
    "description": (
        "SQL Injection attacks manipulate database queries by injecting "
        "malicious SQL commands through application input fields."
    ),
    "technical_details": (
        "Attackers exploit improper input validation to execute unauthorized "
        "database commands."
    ),
    "evidence": [
        "SQL keywords in HTTP parameters",
        "Database error responses"
    ],
    "root_cause": "Improper input validation.",
    "impact": [
        "Database compromise",
        "Data leakage"
    ],
    "mitigation": [
        "Prepared SQL statements",
        "Input validation"
    ],
    "real_world_example": (
        "An attacker injects ' OR 1=1 -- into login fields."
    ),
    "final_verdict": "Malicious — SQL Injection"
},

"XSS": {
    "category": "Web Attacks",
    "severity": "High",
    "description": (
        "Cross-Site Scripting (XSS) injects malicious scripts into "
        "web pages viewed by other users."
    ),
    "technical_details": (
        "The malicious script executes in the victim's browser."
    ),
    "evidence": [
        "Script tags in HTTP payload",
        "Unescaped user input"
    ],
    "root_cause": "Improper output encoding.",
    "impact": [
        "Session hijacking",
        "User data theft"
    ],
    "mitigation": [
        "Output encoding",
        "Content Security Policy"
    ],
    "real_world_example": (
        "A comment form injects malicious JavaScript."
    ),
    "final_verdict": "Malicious — XSS Attack"
},

# ==================================================
# 5. RECONNAISSANCE
# ==================================================

"Port Scan": {
    "category": "Reconnaissance Attacks",
    "severity": "Medium",
    "description": (
        "Port scanning probes network ports to identify open services "
        "and potential attack surfaces."
    ),
    "technical_details": (
        "Tools like Nmap perform automated scans across thousands of ports."
    ),
    "evidence": [
        "Sequential port connection attempts",
        "Multiple connection attempts in short time"
    ],
    "root_cause": "Exposed network services.",
    "impact": [
        "Discovery of vulnerable services"
    ],
    "mitigation": [
        "Firewall filtering",
        "Disable unused ports"
    ],
    "real_world_example": (
        "An attacker scans ports 1–65535 of a server."
    ),
    "final_verdict": "Suspicious — Port Scan Detected"
},

# ==================================================
# 6. MALWARE ACTIVITY
# ==================================================

"C2-Traffic": {
    "category": "Malware Activity",
    "severity": "Critical",
    "description": (
        "Command and Control traffic occurs when compromised systems "
        "communicate with attacker infrastructure."
    ),
    "technical_details": (
        "Malware periodically sends beacon signals to external servers."
    ),
    "evidence": [
        "Periodic outbound connections",
        "Connections to suspicious IP addresses"
    ],
    "root_cause": "Malware infection.",
    "impact": [
        "Remote attacker control",
        "Data theft"
    ],
    "mitigation": [
        "Isolate infected endpoints",
        "Perform malware removal"
    ],
    "real_world_example": (
        "A compromised workstation periodically connects to a botnet server."
    ),
    "final_verdict": "Malicious — Command and Control Communication"
},

# ==================================================
# 7. NORMAL TRAFFIC
# ==================================================

"Benign": {
    "category": "Normal Traffic",
    "severity": "None",
    "description": (
        "Legitimate network traffic generated during normal system operation."
    ),
    "technical_details": "Normal user interactions and application traffic.",
    "evidence": [],
    "root_cause": "",
    "impact": [],
    "mitigation": [],
    "real_world_example": "User browsing a website normally.",
    "final_verdict": "Benign — No Threat Detected"
}

}