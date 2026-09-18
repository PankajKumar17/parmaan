# Coverage Statement

## Supported Attack Classes

The assurance system is designed to detect the following classes of security issues and quality concerns:

### 1. Injection Flaws
- SQL Injection (CWE-89)
- NoSQL Injection
- Command Injection (CWE-78)
- LDAP Injection
- XPath Injection
- Template Injection

### 2. Authentication and Session Management
- Hardcoded Credentials (CWE-798)
- Weak Password Policies
- Insecure Session Storage
- Missing Authentication for Critical Functions
- Weak Randomness in Tokens (CWE-330)

### 3. Sensitive Data Exposure
- Hardcoded Secrets (API keys, cryptographic keys)
- Insecure Data Storage
- Weak Cryptographic Algorithms (CWE-327)
- Missing Encryption of Sensitive Data
- Insecure Transmission of Sensitive Data

### 4. Cross-Site Scripting (XSS)
- Reflected XSS (CWE-79)
- Stored XSS (CWE-79)
- DOM-based XSS
- Improper Output Encoding

### 5. Cross-Site Request Forgery (CSRF)
- Missing CSRF Tokens
- Incorrect CSRF Validation

### 6. Security Misconfiguration
- Default Configurations
- Unnecessary Services Enabled
- Detailed Error Messages Exposing Sensitive Info
- Missing Security Headers
- Directory Listing Enabled

### 7. Vulnerable and Outdated Components
- Known Vulnerable Libraries (via CVE matching)
- Outdated Framework Versions
- Unmaintained Dependencies

### 8. Insufficient Logging and Monitoring
- Missing Audit Logs for Security Events
- Log Injection Vulnerabilities
- Sensitive Data in Logs

### 9. Code Quality Issues
- Potential Null Pointer Dereferences
- Resource Leaks (unclosed file handles, DB connections)
- Infinite Loops
- Unused Code/Dead Code
- Complexity Violations
- Hardcoded Paths

### 10. Configuration Issues
- Insecure Default Settings
- Overly Permissive Permissions
- Debug Mode Enabled in Production
- Container Security Misconfigurations

## Assumptions

1. **Target Accessibility**: The system assumes it has read access to all files in the target directory that need to be analyzed.

2. **Language Support**: The system currently provides robust analysis for:
   - Primary: Python, JavaScript/TypeScript, Java, C/C++, Go
   - Secondary: PHP, Ruby, C#, Rust (limited rule sets)
   - Basic: HTML, CSS, XML, JSON, YAML (structural analysis only)

3. **File Size Limitations**: Individual files larger than 100MB may be skipped or partially analyzed due to memory constraints.

4. **Build Artifacts**: The system analyzes source code and does not require compiled binaries, though it can analyze certain binary formats for embedded strings and metadata.

5. **Configuration Files**: The system assumes standard formats for configuration files (JSON, YAML, INI, properties, XML) and may not parse proprietary formats.

6. **Dependency Resolution**: For dependency analysis, the system assumes standard package managers (pip, npm, Maven, Gradle, etc.) and lockfiles are present when applicable.

7. **Network Isolation**: In air-gapped environments, the system assumes all necessary rule sets, signatures, and ML models are pre-loaded; no external lookups are performed during analysis.

8. **Timestamp Accuracy**: The system assumes the target system's clock is reasonably accurate for timestamp-based analysis (though this is not critical for most detection methods).

## Known Limitations

1. **Zero-Day Vulnerabilities**: The system relies on known vulnerability patterns and may not detect previously unknown (zero-day) vulnerabilities that don't match existing signatures.

2. **Context-Aware Business Logic Flaws**: Complex business logic vulnerabilities that require deep understanding of application-specific workflows may produce false negatives.

3. **Encrypted/Obfuscated Code**: Code that is encrypted, packed, or heavily obfuscated may not be analyzed effectively.

4. **Runtime-Only Vulnerabilities**: Vulnerabilities that only manifest during specific runtime conditions (e.g., race conditions, timing attacks) may not be detected in static analysis.

5. **Environment-Specific Issues**: Issues dependent on specific deployment configurations, infrastructure, or third-party services may not be fully captured.

6. **Multi-Stage Attack Chains**: While individual vulnerabilities are detected, complex attack chains that combine multiple lesser issues may not be flagged as high-risk combinations.

7. **False Positives in ML Components**: Machine learning-based anomaly detection may produce false positives, particularly in codebases with unconventional patterns or domain-specific languages.

8. **Limited Binary Analysis**: Binary analysis is restricted to string extraction, entropy analysis, and basic control flow; deep binary reverse engineering is not performed.

## Conditions/Attacks the System Does Not Support

1. **Dynamic Runtime Attacks**: The system does not execute code during analysis, so it cannot detect:
   - Time-of-check/time-of-use (TOCTOU) race conditions
   - Heap-based buffer overflows requiring actual execution
   - Use-after-free vulnerabilities
   - Kernel-level exploits

2. **Physical/Hardware Attacks**:
   - Side-channel attacks (power analysis, timing, electromagnetic)
   - Fault injection attacks
   - Temperature-based attacks
   - Hardware trojans

3. **Network-Layer Attacks**:
   - DDoS amplification techniques
   - Protocol-level manipulation (unless evident in configuration)
   - Man-in-the-middle attacks requiring network interception
   - DNS spoofing/cache poisoning

4. **Social Engineering**: The system cannot detect vulnerabilities related to human factors:
   - Phishing susceptibility in UI/UX
   - Social engineering attack vectors
   - Insider threat indicators

5. **Supply Chain Attacks (Advanced)**:
   - Compromised build systems (unless evidence exists in source)
   - Timestamp manipulation in version control
   - Steganographic hiding of malware in assets
   - Compiler-level attacks (unless specific patterns are detectable)

6. **Cloud-Specific Vulnerabilities**:
   - Misconfigured cloud IAM policies (beyond basic file analysis)
   - Serverless function vulnerabilities requiring deployment context
   - Container escape techniques (unless evident in Dockerfile/security context)
   - Kubernetes RBAC misconfigurations (requires cluster state)

7. **Legal/Compliance-Specific Issues**:
   - GDPR Article 32 requirements (requires contextual interpretation)
   - Industry-specific regulatory compliance (HIPAA, PCI-DSS, etc.) beyond basic controls
   - Export control violations
   - Patent infringement detection

8. **Advanced Evasion Techniques**:
   - Polymorphic malware detection
   - Fileless malware techniques
   - Living-off-the-land binary (LOLBAS) usage (unless evident in scripts)
   - Encrypted channel detection (without decryption keys)

## Mitigation for Limitations

To address these limitations, the assurance system should be used as part of a comprehensive security program that includes:

1. **Dynamic Application Security Testing (DAST)** for runtime vulnerability detection
2. **Interactive Application Security Testing (IAST)** for context-aware analysis
3. **Manual Code Review** for complex business logic and architectural issues
4. **Penetration Testing** for exploit validation and chaining
5. **Software Composition Analysis (SCA)** tools for deep dependency tracking
6. **Runtime Application Self-Protection (RASP)** for production monitoring
7. **Threat Modeling** sessions to identify design-level issues
8. **Regular Updates** to rule sets, signatures, and ML models as new threats emerge

The system provides strongest value when integrated into a DevSecOps pipeline with appropriate complementary security testing methods.