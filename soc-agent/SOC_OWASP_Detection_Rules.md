### A01:2021 – BROKEN ACCESS CONTROL

#### Rule 1.1: Unauthorized Lateral Movement via Explicit Credentials
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security |
| **Detection Rule Name** | Lateral Movement - Explicit Credentials Usage |
| **Log Indicators** | Event ID 4648 (Logon Using Explicit Credentials); Field: TargetServerName NOT matching source hostname; Repeat count >3 in 10 minutes |
| **Mapped OWASP** | A01 - Broken Access Control |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1550.004 - Use Alternate Authentication Material |
| **Rationale** | Event 4648 indicates "Run As" or credential delegation. Multiple 4648 events across different target systems within short timeframe strongly indicates lateral movement. Attackers use compromised credentials to access additional systems, bypassing access controls. HIGH severity assigned because successful exploitation grants multi-system access and enables privilege escalation chains. Exploitability is high with valid credentials. |
| **Detection Logic** | Aggregate Event ID 4648 by source host. Alert if: (1) TargetServerName differs from source 5+ times/hour OR (2) 10+ unique TargetServerName values in 60 minutes OR (3) TargetServerName matches known sensitive systems (DC, file servers) combined with non-admin source account |

---

#### Rule 1.2: Unauthorized Object Access Attempts
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security |
| **Detection Rule Name** | Unauthorized File/Registry Access Attempts |
| **Log Indicators** | Event ID 4663 (Attempt was made to access object); Field: AccessMask including DELETE, WRITE, MODIFY; SubjectUserName NOT in privileged groups; ObjectType = File or Registry; Repeat count >15 in 5 minutes |
| **Mapped OWASP** | A01 - Broken Access Control |
| **Severity** | **MEDIUM** |
| **MITRE ATT&CK** | T1114 - Email Collection / T1005 - Data from Local System |
| **Rationale** | Event 4663 with WRITE/DELETE masks indicates attempts to modify protected resources. Repeated failures suggest enumeration or brute-force access attempts. MEDIUM severity because this is detection at attempt phase; actual access has not yet been compromised. However, HIGH if access succeeds (4663 with object opened = access granted). Exploitability requires valid account. |
| **Detection Logic** | Filter Event 4663 where AccessMask includes 0x00000002 (WRITE), 0x00010000 (DELETE), or 0x00000010 (MODIFY). Alert if failure count >15/5min OR if objects match sensitive paths (\Admin$, \Sysvol, \Registry). |

---

#### Rule 1.3: Role/Privilege Boundary Violations
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security |
| **Detection Rule Name** | Unauthorized Privilege Grant Attempt |
| **Log Indicators** | Event ID 4704 (User Right Assigned) or 4717 (Access rights granted); SubjectUserName is standard user; PrivilegeType includes SeDebugPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege |
| **Mapped OWASP** | A01 - Broken Access Control |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1134 - Access Token Manipulation / T1548 - Abuse Elevation Control Mechanism |
| **Rationale** | Standard users should never grant privileges to accounts. This violates strict role-based access control and indicates either compromised admin account or local privilege escalation. CRITICAL severity because successful exploitation enables system compromise, credential dumping, and persistence. Direct path to domain compromise. |
| **Detection Logic** | Alert on: Event 4704 or 4717 where SubjectUserName NOT in Administrators/SYSTEM groups. OR any assignment of dangerous privileges (SeDebugPrivilege, SeLoadDriver) regardless of source. |

---

### A02:2021 – CRYPTOGRAPHIC FAILURES

#### Rule 2.1: Weak TLS/SSL Protocol Usage
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Network, Application |
| **Detection Rule Name** | Deprecated TLS Protocol Connection Detected |
| **Log Indicators** | HTTP communication on port 80 (unencrypted); TLS version <1.2 in application logs; Self-signed or expired certificate errors in IIS/Apache logs; Connection to non-standard HTTPS ports (4443, 8443, 9443) via HTTP fallback |
| **Mapped OWASP** | A02 - Cryptographic Failures |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1557 - Man-in-the-Middle / T1040 - Network Sniffing |
| **Rationale** | TLS <1.2 or unencrypted HTTP allows MITM attacks. Attackers intercept session tokens, credentials, and sensitive data. HIGH severity because data confidentiality is completely compromised for affected sessions. Exploitability is trivial on unencrypted channels. TLS 1.0/1.1 support indicates deprecated/legacy systems requiring immediate remediation. |
| **Detection Logic** | Windows IIS: Filter Application logs for "SSLv3", "TLS 1.0", "TLS 1.1" in event descriptions. Linux: Search Apache access logs for plain HTTP requests to /login, /api/auth. Alert on any HTTP (not HTTPS) session resumption attempts. |

---

#### Rule 2.2: Hardcoded Credentials in Configuration Files
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Registry (Windows), System (Linux) |
| **Detection Rule Name** | Plaintext Credentials Stored in Configuration |
| **Log Indicators** | Registry modification to keys containing credential patterns: HKLM\Software\[AppName]\Credentials, password=, pwd=, secret=; Config file reads/writes to .config, .ini, web.config with "password" keywords; File access via auditd to /etc/passwd, /etc/shadow modifications outside package manager |
| **Mapped OWASP** | A02 - Cryptographic Failures |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1555 - Credentials from Password Stores / T1083 - File and Directory Discovery |
| **Rationale** | Plaintext credentials enable immediate unauthorized access. No exploitation required—attacker reads config and gains full system access. CRITICAL because impact is complete system compromise. Exploitability is trivial. Applies to OWASP A02 (Cryptographic Failures) because credentials must be encrypted. |
| **Detection Logic** | Monitor Registry writes to HKCU/HKLM containing password= patterns. Flag web.config reads/writes. Linux: auditd rule tracking /etc/passwd, /etc/shadow access. Scan for keywords: "password", "pwd", "api_key", "secret", "token" in configuration logs. |

---

#### Rule 2.3: Weak Password Hashing Detection
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application |
| **Detection Rule Name** | Weak Cryptographic Hash Algorithm Usage |
| **Log Indicators** | Application logs showing MD5 or SHA-1 hash generation; Plaintext password comparisons in logs; Hash algorithm selection defaults (not explicitly bcrypt/Argon2); Database dump analysis showing <10 rounds salting |
| **Mapped OWASP** | A02 - Cryptographic Failures |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1556 - Modify Authentication Process |
| **Rationale** | MD5/SHA-1 are cryptographically broken; rainbow tables crack them in seconds. Weak salting (few iterations) enables rapid offline cracking. HIGH severity for breach scenario; if password database leaks, millions of accounts compromised. Exploitability requires database access but is guaranteed once obtained. |
| **Detection Logic** | Search application logs for: "MD5", "SHA1", "hash_method=md5", "bcrypt.default_rounds < 10". Monitor database schema for password fields using BINARY(16) or VARCHAR(32) without salt. |

---

### A03:2021 – INJECTION

#### Rule 3.1: SQL Injection Attempt Detection
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, Network |
| **Detection Rule Name** | SQL Injection Payload in HTTP Request |
| **Log Indicators** | HTTP query parameters or POST data containing SQL keywords: UNION SELECT, OR 1=1, DECLARE, EXEC, DROP TABLE, '; --, WAITFOR DELAY; Character encoding sequences (%27, %3B, 0x); Multiple SQL comments in single parameter |
| **Mapped OWASP** | A03 - Injection |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application |
| **Rationale** | SQL injection enables database access/modification without authentication. Attacker can extract all data, modify records, execute stored procedures. CRITICAL severity because impact is total database compromise. Exploitability depends on input validation gaps (common). |
| **Detection Logic** | Regex match on HTTP request parameters: `(\bUNION\b.*\bSELECT\b)|(\bOR\b\s+1\s*=\s*1)|(\bEXEC\b)|(\bDROP\b)|('\s*;\s*--)`. Alert on HTML entity encoding variants. Whitelist legitimate SQL patterns (rare in web apps). |

---

#### Rule 3.2: Cross-Site Scripting (XSS) Attempt Detection
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, Network |
| **Detection Rule Name** | XSS Payload in HTTP Request |
| **Log Indicators** | HTTP parameters containing: <script>, javascript:, onerror=, onclick=, onload=, <iframe>, eval(, alert(; URL encoding of script tags (%3Cscript%3E); SVG/Event handlers (onmouseover, onmousedown); Content-Type mismatch (HTML returned as text/plain) |
| **Mapped OWASP** | A03 - Injection |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1598 - Phishing / T1566 - Phishing: Email |
| **Rationale** | XSS steals session cookies, credentials, and executes malicious code in victim browsers. HIGH severity because impact affects multiple users (session hijacking, credential theft). Exploitability is high if input validation is weak. Stored XSS elevates to CRITICAL. |
| **Detection Logic** | Regex: `(<script[^>]*>)|(\bonload\s*=)|(javascript:)|(eval\s*\()`. Track reflected payloads: if same parameter value appears in HTTP response unchanged, flag as reflected XSS. Monitor Set-Cookie and Authorization headers for tampering indicators. |

---

#### Rule 3.3: Command Injection Detection
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, System |
| **Detection Rule Name** | OS Command Injection Attempt |
| **Log Indicators** | HTTP parameters containing shell metacharacters: $(command), `;cmd;`, `|cmd|`, `&cmd&`, backticks, `\x00` (null byte); Process creation from web app (IIS/Apache/Tomcat) spawning cmd.exe, /bin/bash, /bin/sh outside expected paths; Command sequences in application logs: ping, whoami, id, cat /etc/passwd |
| **Mapped OWASP** | A03 - Injection |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1059 - Command and Scripting Interpreter |
| **Rationale** | Command injection allows arbitrary OS command execution with application privilege level. CRITICAL because impact is full application server compromise, lateral movement, data exfiltration. Exploitability is high if OS commands are called with user input. |
| **Detection Logic** | Alert on: HTTP parameters containing regex `[;|&\$\(\)]` combined with shell commands. Windows: Event 4688 with ParentImage=w3wp.exe, iisexpress.exe spawning cmd.exe/powershell.exe. Linux: Auditd detect execve by www-data user calling /bin/bash. |

---

### A04:2021 – INSECURE DESIGN

#### Rule 4.1: Privilege Management Flaws
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, Security |
| **Detection Rule Name** | Improperly Restricted Administrative Access |
| **Log Indicators** | User account without admin privileges successfully accessing admin-only resources; Event ID 4673 (Privileged Service Called) from standard user account; Linux: sudo execution without password (NOPASSWD in /etc/sudoers); Web app enforcing permissions client-side only (POST parameter user_role=admin); Missing authentication checks on sensitive endpoints |
| **Mapped OWASP** | A04 - Insecure Design (CWE-269: Improper Privilege Management) |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1548 - Abuse Elevation Control Mechanism |
| **Rationale** | Privilege management flaws allow users to perform actions beyond their role. HIGH severity because attacker gains unauthorized capabilities (admin actions from user account). Exploitability is high if client-side validation only or missing authorization checks server-side. Impact includes data access, system modification. |
| **Detection Logic** | Flag Event 4673 from non-admin users. Linux: auditd rule `-w /etc/sudoers -p wa` detects NOPASSWD entries. Web apps: Log all HTTP requests; flag requests to /admin or protected endpoints from users without admin role in session token. |

---

#### Rule 4.2: Insufficient Data Validation (Client-Side Only)
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application Network |
| **Detection Rule Name** | Data Validation Bypass via Tampered Request |
| **Log Indicators** | POST requests with data exceeding schema constraints (e.g., age field >150 or negative, email field with SQL keywords, username with special chars not validated server-side); Browser developer tools detect no server-side response rejection; Same request format sent via raw TCP bypassing browser |
| **Mapped OWASP** | A04 - Insecure Design (CWE-501: Trust Boundary Violation) |
| **Severity** | **MEDIUM** |
| **MITRE ATT&CK** | T1585 - Compromise Accounts |
| **Rationale** | Client-side validation can be bypassed via browser tools or direct network requests. MEDIUM severity because impact depends on what data is corrupted (financial transaction HIGH, comment field LOW). Exploitability is trivial. Indicates architectural flaw requiring server-side re-validation. |
| **Detection Logic** | Correlate: HTTP requests containing data outside acceptable ranges (use schema/context) + server accepts without error logging. Flag requests with Content-Length mismatches or modified authentication tokens. Monitor for curl/Python/raw socket requests to endpoints (bypassing JS validation). |

---

#### Rule 4.3: Missing Threat Modeling Controls
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application |
| **Detection Rule Name** | Suspicious Business Logic Bypass |
| **Log Indicators** | HTTP requests manipulating business logic: booking cinema seats for price <0, promo codes generating negative charges, quantity fields exceeding physical inventory, shipping cost set to zero, purchase order timestamp older than current date, account transfer value exceeding daily limit without rate-limiting rejection |
| **Mapped OWASP** | A04 - Insecure Design (CWE-799: Improper Control of Interaction Frequency) |
| **Severity** | **MEDIUM** to **HIGH** |
| **MITRE ATT&CK** | T1583 - Acquire Infrastructure |
| **Rationale** | Business logic flaws allow attackers to bypass intended workflows (e.g., monopolize inventory, overdraft accounts). MEDIUM if financial loss is bounded; HIGH if enables fraud/abuse at scale. Exploitability requires understanding business domain. Impact is financial loss or service degradation. |
| **Detection Logic** | Baseline normal transaction patterns. Alert on: negative prices in POST data, quantity fields >physical threshold, timestamp parameters in past/future, repeated use of same promo code with different user accounts. Correlate: User A initiates transaction, User B completes it. |

---

### A05:2021 – SECURITY MISCONFIGURATION

#### Rule 5.1: Default Credentials Active on Critical Services
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Security, Network |
| **Detection Rule Name** | Default Credential Authentication Success |
| **Log Indicators** | Successful authentication (Event ID 4624, Linux auth.log) using accounts: admin, root, guest, administrator, test with generic passwords (password, admin, 123456); IIS/Apache logs showing successful request from localhost with basic auth "admin:admin"; Database connection logs from app servers to database using sa, postgres, root accounts |
| **Mapped OWASP** | A05 - Security Misconfiguration |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1078 - Valid Accounts |
| **Rationale** | Default credentials provide immediate unauthorized access to systems. No exploitation required—attacker uses published defaults. CRITICAL severity because impact is complete system compromise of critical service. Exploitability is trivial. All public documentation lists defaults; attackers scan for them. |
| **Detection Logic** | Alert on authentication success to admin/root/sa accounts with static passwords. Create allowlist of legitimate admin account names. Flag logins to critical services (SQL Server, Oracle, database) from non-application accounts. Check IIS/Apache access logs for HTTP basic auth with predictable credentials. |

---

#### Rule 5.2: Unnecessary Ports/Services Exposed
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Network |
| **Detection Rule Name** | Unauthorized Service Port Access Attempt |
| **Log Indicators** | Inbound connections to non-standard ports: 3389 (RDP) from non-corporate IPs, 3306 (MySQL), 5432 (PostgreSQL) from external networks, 5900 (VNC), 1433 (SQL Server) from internet; Successful connection to admin ports (135, 139, 445 SMB) from non-domain hosts; FTP, Telnet connections on ports 21, 23 (unencrypted protocols) |
| **Mapped OWASP** | A05 - Security Misconfiguration |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application / T1046 - Network Service Scanning |
| **Rationale** | Exposed database/admin ports allow direct unauthorized access. HIGH severity because attackers bypass application layer, directly exploit database. Exploitability depends on service hardening but is high for unpatched services. Impact is data breach/system compromise. |
| **Detection Logic** | Baseline inbound network flows. Alert on: Inbound to RDP (3389), MySQL (3306), PostgreSQL (5432), SMB (445) from non-whitelisted IP ranges. Linux: Monitor open ports via ss/netstat; flag listening on 0.0.0.0 for privileged services. |

---

#### Rule 5.3: Security Headers Missing
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Network, Application |
| **Detection Rule Name** | Missing Critical Security Headers in HTTP Response |
| **Log Indicators** | HTTP response lacks: Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security (HSTS), X-XSS-Protection; HTTPS connections served with self-signed/expired certificates; Cookies missing Secure/HttpOnly flags in Set-Cookie headers |
| **Mapped OWASP** | A05 - Security Misconfiguration |
| **Severity** | **MEDIUM** |
| **MITRE ATT&CK** | T1598 - Phishing |
| **Rationale** | Missing security headers enable attacks: clickjacking (missing X-Frame-Options), MIME-sniffing (missing X-Content-Type-Options), XSS (missing CSP), cookie theft (missing HttpOnly). MEDIUM severity because protections are missing but exploitation requires additional attack (e.g., phishing for clickjacking). Exploitability is high. |
| **Detection Logic** | Capture HTTP responses; parse headers. Alert if HSTS, CSP, X-Frame-Options, X-Content-Type-Options absent. Check Set-Cookie: flag if Secure flag missing on HTTPS or HttpOnly missing. Correlate: High-value endpoints (login, payment) without CSP warrant higher alert priority. |

---

### A06:2021 – VULNERABLE AND OUTDATED COMPONENTS

#### Rule 6.1: Known Vulnerable Library/Framework Exploitation
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, System |
| **Detection Rule Name** | Exploitation Attempt Against Known Vulnerable Component |
| **Log Indicators** | HTTP requests targeting known vulnerable endpoints: /upload (unrestricted file upload, CWE-434), Struts version <2.3.32 with OGNL injection pattern, Log4j version <2.17.0 with ${ pattern (Log4Shell), Spring version <5.2.20 with SpEL injection (Spring4Shell); Exception stack traces in logs revealing vulnerable library names/versions; Failed attempts to load patched library followed by fallback to vulnerable version |
| **Mapped OWASP** | A06 - Vulnerable and Outdated Components |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application |
| **Rationale** | Known vulnerabilities in libraries have public exploits and full impact assessment. CRITICAL severity because: (1) Exploitability is trivial (public PoCs), (2) Impact is arbitrary code execution/data breach, (3) No patching means guaranteed compromise timeline. |
| **Detection Logic** | Maintain CVE database linked to library versions. Alert on HTTP patterns matching known exploits: Struts ${, Log4j ${jndi:}, Spring SpEL #{}, unrestricted /upload endpoints. Exception messages revealing Struts, Log4j, Spring version numbers. Database dependency checks: query application metadata for library versions; flag if any version in NVD vulnerable list. |

---

#### Rule 6.2: Outdated Operating System / Runtime
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | System, Application |
| **Detection Rule Name** | Exploitation Attempt Against Outdated OS/Runtime |
| **Log Indicators** | OS build number indicating unsupported version: Windows XP (build <6000), Windows 7 (build <7600) past end-of-life, Java version <8u131 with known RCE, Python 2.x EOL runtime; Patch Tuesday absent for >90 days; Security bulletin check reveals unpatched OS; Exploit code for specific OS vulnerability (e.g., EternalBlue/MS17-010) detected in network traffic |
| **Mapped OWASP** | A06 - Vulnerable and Outdated Components |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application / T1566 - Phishing |
| **Rationale** | Unsupported OS receives no security patches. CRITICAL because: (1) All known vulnerabilities are unpatched, (2) Exploitation is trivial with public exploits, (3) Affects all running applications. EternalBlue alone compromised millions of machines (WannaCry, NotPetya). |
| **Detection Logic** | Query System event ID 6 (OS boot) to extract OS version. Parse: wmic os get version, uname -r. Alert if build/version is EOL or >6 months without patch. Network IDS signature matching EternalBlue, CVE-2017-0144 SMB traffic. |

---

#### Rule 6.3: Unmaintained Third-Party Component Dependency
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application |
| **Detection Rule Name** | Unmaintained or Unsupported Library in Use |
| **Log Indicators** | Application dependency report shows library without updates >2 years; Exception/error messages revealing archived library (e.g., "Apache Commons Collections 3.x"); Failed library load triggering fallback to older version; Startup logs showing deprecated API calls with "will be removed in X" warnings |
| **Mapped OWASP** | A06 - Vulnerable and Outdated Components (CWE-1104: Use of Unmaintained Third-Party Components) |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application |
| **Rationale** | Unmaintained libraries don't receive security patches for newly discovered CVEs. HIGH severity because zero-day exploits are unpatched indefinitely. Exploitability increases over time as new vulnerabilities are discovered. Impact includes arbitrary code execution if RCE vulnerability exists. |
| **Detection Logic** | Require Software Bill of Materials (SBOM) with last-update timestamps. Alert if any library last updated >2 years ago or repository marked "archived". Correlate with CVE databases: if unmaintained library has known CVE, elevate to CRITICAL. |

---

### A07:2021 – IDENTIFICATION AND AUTHENTICATION FAILURES

#### Rule 7.1: Brute-Force Attack on Authentication
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Security, Application |
| **Detection Rule Name** | Brute-Force Login Attempt Detected |
| **Log Indicators** | Event ID 4625 (Failed Logon) from single source with >10 failures in 10 minutes against different accounts; Linux auth.log: "Failed password for invalid user" >20 in 5 minutes from same IP; Event ID 4771 (Kerberos Pre-Auth Failed) >30 in 5 minutes (Kerbrute tool); Account lockout cascades: Event ID 4740 (Account Lockout) for multiple accounts in succession |
| **Mapped OWASP** | A07 - Identification and Authentication Failures |
| **Severity** | **MEDIUM** to **HIGH** |
| **MITRE ATT&CK** | T1110 - Brute Force |
| **Rationale** | Brute-force attacks test passwords at scale. MEDIUM severity if failed (account locked/alert sent); HIGH if successful (4625 followed by 4624 success). Exploitability depends on password strength and account lockout policy. Impact is unauthorized access. |
| **Detection Logic** | Aggregate Event 4625 by source IP and target account. Alert if: 10+ failures in 10min OR 20+ failures in 60min OR 5+ different target accounts from same source in 5min. Linux: Parse auth.log failed attempts; alert on >15/5min from single IP. |

---

#### Rule 7.2: Weak Session Management / Session Hijacking
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, Network |
| **Detection Rule Name** | Session Token Reuse or Theft Detected |
| **Log Indicators** | HTTP requests with same Session ID from different source IPs within seconds; Session cookie lacks Secure/HttpOnly flags; Set-Cookie header transmits session ID over unencrypted HTTP (port 80); Session ID reuse after long idle time (>4 hours); Rapid geographic IP location changes for same session (e.g., USA to China in 2 minutes) |
| **Mapped OWASP** | A07 - Identification and Authentication Failures |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1539 - Steal Web Session Cookie / T1552 - Unsecured Credentials |
| **Rationale** | Session hijacking allows attacker to act as authenticated user without credentials. HIGH severity because attacker gains full user access. Exploitability depends on cookie protection (if HttpOnly missing, trivial via XSS). Impact is account takeover. |
| **Detection Logic** | Parse HTTP headers: extract Session ID, source IP, timestamp. Alert on: same Session ID from 2+ IPs within 60 seconds. Check Set-Cookie: flag if Secure or HttpOnly missing. Geolocate source IPs; if 2 requests from same session are >5000km apart in <5min, flag. |

---

#### Rule 7.3: Credential Stuffing / Account Enumeration
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, Security |
| **Detection Rule Name** | Credential Stuffing Attack Signature |
| **Log Indicators** | High volume of login attempts from single IP across many usernames (>50/min); Event 4625 failures for accounts known not to exist (invalid user); Timing pattern: consistent 1-2 second intervals between login attempts (bot behavior); Same source IP rotating User-Agent headers; POST requests to /login endpoint with varying username+password from wordlists |
| **Mapped OWASP** | A07 - Identification and Authentication Failures |
| **Severity** | **MEDIUM** |
| **MITRE ATT&CK** | T1110.004 - Credential Stuffing |
| **Rationale** | Credential stuffing tests stolen password databases. MEDIUM severity because attack is noisy and detectable; successful exploitation is low if passwords are strong/unique. High impact if valid credentials are found. Exploitability is high (automated tools). |
| **Detection Logic** | Alert on: >30 login attempts/minute to /login from single IP. Flag if targeted usernames match common patterns or known leaked account databases. Detect timing regularity: if login attempts occur at exactly 1.5-second intervals (bot behavior), alert. Whitelist admin accounts and legitimate API users. |

---

### A08:2021 – SOFTWARE AND DATA INTEGRITY FAILURES

#### Rule 8.1: Unauthorized Software Update / Code Injection
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | System, Application, Registry |
| **Detection Rule Name** | Integrity Violation: Unauthorized Code Update |
| **Log Indicators** | Application binary (DLL, EXE, .so, .jar) replaced without package manager (event ID 4670 - Registry object created/deleted for AppData\Local\Program Files); Hash mismatch: Known-Good file hash database (HIPS/sysmon Event ID 11) shows different MD5/SHA-256 for binary; Unsigned driver loaded (Event ID 6) on system requiring signed drivers; CI/CD pipeline webhook triggered from unauthorized repository; Application startup logs showing "assembly loaded from unexpected location" or version mismatch |
| **Mapped OWASP** | A08 - Software and Data Integrity Failures |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1195 - Supply Chain Compromise / T1574 - Hijack Execution Flow |
| **Rationale** | Replacing application binaries enables arbitrary code execution. CRITICAL because: (1) Impact is full application compromise, (2) Exploitability depends on write permissions (if writable, trivial), (3) Enables persistence and malware distribution. |
| **Detection Logic** | Maintain cryptographic hash database of all production binaries. Alert on: File modification events (4670, Event ID 11) for .exe, .dll, .so files outside expected package managers. Correlate: hash mismatch with no corresponding Windows Update/patch event. Monitor registry for Assembly Binding Redirection (CWE-426). |

---

#### Rule 8.2: Insecure Deserialization / Untrusted Data Processing
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application |
| **Detection Rule Name** | Malicious Deserialization Object Detected |
| **Log Indicators** | Application logs showing deserialization of untrusted Java objects (ObjectInputStream.readObject), Python pickle.load(), .NET BinaryFormatter; HTTP POST/PUT requests with serialized payload containing type gadget chains (CommonsCollections, Spring, ROME); Exception messages revealing "Gadget Chain" or known RCE classes; Process spawned from application container immediately after deserialization event |
| **Mapped OWASP** | A08 - Software and Data Integrity Failures (related to CWE-502: Deserialization of Untrusted Data) |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application |
| **Rationale** | Insecure deserialization allows arbitrary code execution via gadget chains. CRITICAL because: (1) Exploitability is high (public gadgets + ysoserial tool), (2) Impact is RCE with application privilege. |
| **Detection Logic** | Alert on HTTP requests with Java serialization markers (0xACED0005) or base64-encoded versions. Flag exception messages containing "gadget", "CommonsCollections", "InvokerTransformer". Correlate: Deserialization event + process creation (4688) for unexpected child processes. |

---

### A09:2021 – SECURITY LOGGING AND MONITORING FAILURES

#### Rule 9.1: Insufficient Security Event Logging
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | System, Application |
| **Detection Rule Name** | Missing Critical Security Events in Logs |
| **Log Indicators** | Large time gaps between consecutive login events (>8 hours on active system indicating log deletion); Event ID 1102 (Event Log cleared) without corresponding IT ticket; Application logs with no audit trail for sensitive operations (password change, permission grant, data access); /var/log/audit/audit.log has zero entries for >24 hours on active system; Web application logs missing authentication events despite traffic in firewall logs |
| **Mapped OWASP** | A09 - Security Logging and Monitoring Failures |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1070 - Indicator Removal / T1562.008 - Disable or Modify Windows Event Logging |
| **Rationale** | Missing logs prevent incident response and forensics. HIGH severity because: (1) Indicates either compromise (logs deleted) or misconfiguration (logging disabled), (2) Enables attacker to hide activities, (3) Prevents breach detection. Exploitability requires admin access; impact is undetectable compromise. |
| **Detection Logic** | Establish logging baselines: expected events/hour for production systems. Alert if: Event ID 1102 detected (log clear). Flag gaps: if 4624 (login) events cease for >4 hours on active system. Monitor auditd status: ausearch should return results for past 24 hours; silence indicates corruption/deletion. |

---

#### Rule 9.2: Inadequate Alerting / Response Capability
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | System, Application |
| **Detection Rule Name** | Alert Threshold Misconfiguration or Suppression |
| **Log Indicators** | Monitoring system configured with thresholds so high that alerts never fire (e.g., failed login alert set to >1000/hour); Multiple severe events (4625 brute force, registry tampering, service start from unusual path) with no corresponding alerts/notifications; Syslog forwarding disabled or redirected to /dev/null; Monitoring agent offline (Event ID 4688 + no subsequent events) for extended period; Alert queue full/overflowing with stale alerts (>30-day-old alerts still in queue) |
| **Mapped OWASP** | A09 - Security Logging and Monitoring Failures |
| **Severity** | **MEDIUM** |
| **MITRE ATT&CK** | T1562 - Impair Defenses |
| **Rationale** | Misconfigured alerting renders logging ineffective. MEDIUM severity because events are logged (recovery possible) but in-real-time detection is compromised. Impact is delayed incident detection, prolonged compromise. Exploitability requires understanding alert thresholds. |
| **Detection Logic** | Query SIEM/alerting system configuration: validate thresholds match risk profile (e.g., failed login >5/min is reasonable; >1000/min indicates misconfiguration). Check logging agent status: alert if collection agent offline >1 hour. Monitor alert queue age: flag if oldest alert >7 days (backlog). |

---

#### Rule 9.3: Sensitive Information Logged Improperly
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, System |
| **Detection Rule Name** | Sensitive Data Exposure in Logs |
| **Log Indicators** | Application error logs containing full SQL queries with plaintext WHERE clause data; HTTP request/response logs capturing Authorization headers (Bearer tokens, API keys); Stack traces including local file paths or environment variables; Database connection strings logged with passwords; /var/log files world-readable (chmod 644) containing user credentials; Windows event logs with cleartext password attempts in event description |
| **Mapped OWASP** | A09 - Security Logging and Monitoring Failures (CWE-532: Insertion of Sensitive Information into Log File) |
| **Severity** | **MEDIUM** |
| **MITRE ATT&CK** | T1552 - Unsecured Credentials |
| **Rationale** | Logs contain credentials/PII but are often accessible to low-privilege users or backup systems. MEDIUM severity because impact is exposure of secrets logged for legitimate reasons. Exploitability requires log access (often available to developers). Impact is credential compromise. |
| **Detection Logic** | Scan application logs for patterns: "password=", "api_key=", "token=", "Authorization:", "password:", SELECT.*WHERE. Alert on stack traces containing /home/username or %USERPROFILE%. Check file permissions: alert if /var/log files have world-read permissions. Redact sensitive patterns in logs before central storage. |

---

### A10:2021 – SERVER-SIDE REQUEST FORGERY (SSRF)

#### Rule 10.1: SSRF Exploitation Attempt
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Application, Network |
| **Detection Rule Name** | Server Making Request to Internal Resources |
| **Log Indicators** | Application initiates connection to private IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 169.254.0.0/16) after processing user-supplied URL parameter; HTTP request with url= parameter containing localhost or 127.0.0.1; Connection attempt to AWS metadata endpoint (169.254.169.254:80); Application logs showing "Unable to connect to http://internal-service" after processing untrusted input; Firewall logs showing outbound connection from application server to database server (should communicate via internal network only) triggered by external HTTP request |
| **Mapped OWASP** | A10 - Server-Side Request Forgery |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1090.004 - Proxy via SSRF / T1080 - Tee Cloud Instance Metadata |
| **Rationale** | SSRF enables attacker to: (1) Access internal services (admin panels, databases), (2) Steal cloud metadata (AWS credentials, GCP tokens), (3) Perform internal reconnaissance. HIGH severity because impact includes internal service compromise and credential theft. Exploitability is high if URL validation is weak. |
| **Detection Logic** | Monitor outbound connections initiated by web application. Alert if: (1) Destination IP is in private ranges AND source HTTP request contains url/uri/endpoint parameter, (2) Connection to 169.254.169.254 (AWS metadata), (3) Connection to localhost:xxxx ports (admin services). Whitelist legitimate internal services application is allowed to contact. |

---

#### Rule 10.2: SSRF Reconnaissance / Metadata Access
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows, Linux |
| **Log Type** | Network, Application |
| **Detection Rule Name** | Metadata Service Access via SSRF |
| **Log Indicators** | HTTP request to http://169.254.169.254/latest/meta-data (AWS), http://metadata.google.internal/computeMetadata (GCP), http://169.254.169.254:80/openstack (OpenStack); Application logs showing successful connection and data retrieval; Response contains cloud instance credentials (AKIA keys, temporary tokens); Subsequent use of stolen credentials in AWS API calls (AssumeRole, ListBuckets) from external IP |
| **Mapped OWASP** | A10 - Server-Side Request Forgery |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1552 - Unsecured Credentials / T1526 - Gather Victim Cloud Infrastructure Information |
| **Rationale** | Metadata endpoint access grants cloud credentials. CRITICAL because: (1) Impact is cloud account compromise, (2) Exploitability is high (documented endpoints), (3) Leads to lateral movement and data exfiltration. AWS metadata endpoints accessible by default. |
| **Detection Logic** | Alert on: Any outbound connection to 169.254.169.254 or metadata.google.internal or metadata.alibaba.com from application servers. Flag HTTP responses containing "AccessKeyId", "SecretAccessKey", "Token" from these endpoints. Correlate: Metadata access + AWS API calls from same credentials = confirmed compromise. |

---

## Additional Detections: Malware Persistence & Registry Tampering

#### Rule A-1: Scheduled Task Creation for Persistence
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security, System |
| **Detection Rule Name** | Suspicious Scheduled Task Creation |
| **Log Indicators** | Event ID 4698 (Scheduled Task Created); TaskName contains suspicious patterns: Update, Windows_Patch, Svc*, hidden names starting with $; TaskPath = \Microsoft\Windows\ but created by non-SYSTEM account; Command line contains obfuscation (base64, PowerShell encoded); Non-standard schedule: every minute, every hour continuously |
| **Mapped OWASP** | A01 - Broken Access Control (Persistence / Lateral Movement) |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1053.005 - Scheduled Task/Job |
| **Rationale** | Scheduled tasks enable persistent malware execution. HIGH severity because: (1) Persistence survives reboot, (2) Execution is automatic, (3) Often used by advanced malware (Emotet, Ryuk). Exploitability depends on initial access. |
| **Detection Logic** | Alert on: Event 4698 from non-SYSTEM accounts. Flag TaskName containing suspicious keywords (Svc, Upd, Windows_Patch, hidden). Baseline legitimate scheduled tasks; flag deviations. Check command line for encoded PowerShell or suspicious binaries (certutil, BITSAdmin for file download). |

---

#### Rule A-2: Service Binary Path Modification
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security, System |
| **Detection Rule Name** | Service Executable Path Hijacking |
| **Log Indicators** | Event ID 4697 (Service Installed) with ImagePath pointing to non-standard location (temp, AppData, root C:\ drive); Service startup type changed to "auto" via Event ID 7040 for newly created service; Registry modification event ID 4657: HKLM\System\Services\[ServiceName]\ImagePath points to user-writable path; Service created but binary doesn't exist (indicates pre-positioning attack) |
| **Mapped OWASP** | A01 - Broken Access Control / A05 - Security Misconfiguration |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1574.010 - Hijack Execution Flow: Service File Permissions Weakness |
| **Rationale** | Service binaries run as SYSTEM. Modifying ImagePath to attacker-controlled binary grants SYSTEM code execution. CRITICAL because: (1) Persistence, (2) SYSTEM privilege, (3) Trivial exploitation if service permissions are writable. |
| **Detection Logic** | Alert on: Event 4697 where ImagePath not in Program Files or System32. Event 4657 registry modification to HKLM\System\Services\*/ImagePath. Validate: binary exists and is legitimately signed. Baseline legitimate service ImagePath values; flag deviations. |

---

#### Rule A-3: Suspicious DLL Injection / Hijacking
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security, System |
| **Detection Rule Name** | DLL Load from Unusual Path (DLL Side-Loading) |
| **Log Indicators** | Event ID 4663 + 4656 (Handle request to DLL in AppData, %TEMP%, Downloads); LoadImage operation on DLL not in System32, Program Files, or signed locations; Sysmon Event ID 3 (Network Connection) from process that just loaded suspicious DLL; Registry Event ID 4657: HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System modified (disable UAC); Process execution from directory with user-writable permissions combined with DLL load |
| **Mapped OWASP** | A08 - Software and Data Integrity Failures / A03 - Injection |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1574.002 - DLL Side-Loading |
| **Rationale** | DLL side-loading hijacks legitimate application to load malicious DLL. CRITICAL because: (1) Trusted application as parent process (evasion), (2) Arbitrary code execution, (3) Persistence via legitimate binary. |
| **Detection Logic** | Alert on: Sysmon Event 7 (Image Loaded) where ImageLoaded path is in AppData, %TEMP%, user home directory. Baseline known DLLs loaded by each application; flag new DLLs. Correlate: DLL load + network connection = C2 callback. |

---

#### Rule A-4: WMI Event Consumer Persistence
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Security, System |
| **Detection Rule Name** | Suspicious WMI Persistence Mechanism |
| **Log Indicators** | Event ID 4657: Registry modification to HKLM\Software\Microsoft\Wbem\CIMV2\ or HKCU\Software\Microsoft\Wbem; WMI Event Subscription creation (EventFilter, EventConsumer, Binding registry entries); PowerShell log: Register-WmiEvent or Set-WmiInstance commands; Command line contains wmic.exe with "create EventFilter" or "create LogicalFileConsumer" |
| **Mapped OWASP** | A01 - Broken Access Control (Persistence) |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1546.003 - Event Triggered Execution: WMI Event Subscription |
| **Rationale** | WMI Event Consumers execute arbitrary code on specific system events (file creation, process start). HIGH severity because: (1) Triggers persistence without scheduled tasks, (2) Difficult to detect, (3) Common in APT (Poison Ivy, APT28). |
| **Detection Logic** | Alert on: PowerShell log containing Register-WmiEvent or wmic.exe with EventFilter/Consumer keywords. Registry event ID 4657 for HKLM\Software\Microsoft\Wbem modifications. Query WMI repository for suspicious consumers: wmic logicaldisk get name, wmic /namespace:\\root\subscription PATH __EventFilter get __ClassName,__Xml. |

---

#### Rule A-5: Registry Run Key Modification for Persistence
| **Dimension** | **Value** |
|---|---|
| **OS** | Windows |
| **Log Type** | Registry |
| **Detection Rule Name** | Suspicious Auto-Run Registry Entry Created |
| **Log Indicators** | Event ID 4657: Registry value created/modified in HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run, RunOnce, RunServices; Command path contains obfuscation or unusual location (AppData, %TEMP%, UNC path); Value points to script (VBS, JS, PowerShell) instead of EXE; Entry created outside business hours; Entry created by non-admin account |
| **Mapped OWASP** | A01 - Broken Access Control (Persistence) |
| **Severity** | **HIGH** |
| **MITRE ATT&CK** | T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys |
| **Rationale** | Registry Run entries execute at user login. HIGH severity because: (1) Persistence survives reboot, (2) Trivial to check at runtime, (3) Foundation for ransomware/botnet persistence. |
| **Detection Logic** | Alert on: Event 4657 for HKLM\Software\Microsoft\Windows\CurrentVersion\Run*. Validate: command path exists and is legitimate. Flag entries pointing to %TEMP%, AppData, or UNC paths. Baseline legitimate Run entries (antivirus, management tools); alert on new additions. |

---

#### Rule A-6: /etc/sudoers Unauthorized Modification (Linux)
| **Dimension** | **Value** |
|---|---|
| **OS** | Linux |
| **Log Type** | Audit (auditd) |
| **Detection Rule Name** | Unauthorized sudoers File Modification |
| **Log Indicators** | Auditd event: -w /etc/sudoers -p wa (watch write/append); Field: euid != 0 (non-root modification); ausearch output showing write/append to /etc/sudoers outside of legitimate sudo tools (visudo); /etc/sudoers content check: NOPASSWD entries, wildcard commands (ALL), new user entries outside change windows |
| **Mapped OWASP** | A01 - Broken Access Control / A04 - Insecure Design (privilege management) |
| **Severity** | **CRITICAL** |
| **MITRE ATT&CK** | T1548.004 - Abuse Elevation Control Mechanism: Sudo/Su |
| **Rationale** | /etc/sudoers controls sudo privileges. Unauthorized modification grants sudo to attacker account. CRITICAL because: (1) Complete privilege escalation, (2) Persistence (privilege persists even if password compromised), (3) Trivial to exploit with write access. |
| **Detection Logic** | Enable auditd rule: `-w /etc/sudoers -p wa -k sudoers_changes`. Alert on: ausearch output showing write to /etc/sudoers. Compare /etc/sudoers hash against baseline (tripwire/aide). Flag entries: NOPASSWD (password-less sudo), *, wildcards, new accounts added. |

---

## Detection Rule Severity Justification Framework

### CRITICAL Severity Justification
- **Exploitability**: Trivial to low complexity (public PoC, default behavior, common tools)
- **Impact**: Complete system/application compromise OR data breach affecting all users
- **Examples**: RCE, privilege escalation, authentication bypass, default credentials, known vulnerable components

### HIGH Severity Justification
- **Exploitability**: Low to medium complexity (requires some configuration/knowledge)
- **Impact**: Significant system access OR data exposure for subset of users
- **Examples**: Lateral movement, credential theft, SSRF to internal services, missing security headers

### MEDIUM Severity Justification
- **Exploitability**: Medium complexity (requires knowledge of system architecture)
- **Impact**: Partial system access OR data exposure limited in scope
- **Examples**: Weak TLS, brute-force (with account lockout), business logic flaws, insufficient logging

### LOW Severity Justification
- **Exploitability**: High complexity (requires deep knowledge and multiple steps)
- **Impact**: Limited scope, information disclosure only, no direct access
- **Examples**: Information leakage in error messages, timing attacks, weak password hints

---

## MongoDB Query Examples for Rule Implementation

```javascript
// Rule 1.1: Lateral Movement via 4648
db.windows_security_logs.aggregate([
  {$match: {event_id: 4648, log_time: {$gte: new Date(Date.now()-600000)}}},
  {$group: {_id: "$source_host", targets: {$push: "$target_server"}, count: {$sum: 1}}},
  {$match: {count: {$gte: 3}}}
])

// Rule 3.1: SQL Injection Detection
db.http_logs.find({
  "$or": [
    {request_body: {$regex: /UNION.*SELECT|OR\s+1\s*=\s*1/i}},
    {query_params: {$regex: /UNION.*SELECT|EXEC|DROP/i}}
  ]
})

// Rule 6.1: Known Vulnerable Library Detection
db.application_dependencies.find({
  "$or": [
    {library: "log4j", version: {$lt: "2.17.0"}},
    {library: "struts2", version: {$lt: "2.3.32"}},
    {library: "spring", version: {$lt: "5.2.20"}}
  ]
})

// Rule 8.1: File Hash Integrity Check
db.file_hashes.aggregate([
  {$match: {path: /\.exe$|\.dll$|\.so$/}},
  {$lookup: {
    from: "known_good_hashes",
    localField: "path",
    foreignField: "path",
    as: "baseline"
  }},
  {$match: {"$expr": {$ne: ["$hash", {$arrayElemAt: ["$baseline.hash", 0]}]}}}
])
```


