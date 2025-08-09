# ESC1 Scanner

> **The Schrödinger's ESC1 Vulnerability** - A comprehensive tool for auditing Active Directory Certificate Services to identify ESC1 (Escalation of Privilege via Certificate Templates) vulnerabilities.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Research](https://img.shields.io/badge/Research-Security%20Vulnerability-orange.svg)](https://github.com/yourusername/esc1_scanner)

## 📋 Table of Contents

- [Overview](#overview)
- [Research Background](#research-background)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Technical Details](#technical-details)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

## 🔍 Overview

ESC1 Scanner is a sophisticated security research tool designed to audit Active Directory Certificate Services environments for ESC1 vulnerabilities. The tool performs comprehensive enumeration of certificate authorities, templates, and security descriptors to identify misconfigurations that could lead to privilege escalation.

### What is ESC1?

ESC1 (Escalation of Privilege via Certificate Templates) is a critical vulnerability in Active Directory Certificate Services where low-privileged users can escalate their privileges by requesting certificates with specific configurations. The vulnerability occurs when certificate templates are misconfigured to allow:

1. **No Manager Approval Required** - Requests are not held for manual approval
2. **Subject Alternative Name (SAN) Allowed** - Enrollees can specify SAN in CSR
3. **No Recovery Agent Signature Required** - No additional signatures needed
4. **Authentication EKUs Present** - Certificates can be used for authentication
5. **Low-Privileged Users Have Enrollment Rights** - Non-admin users can enroll

## 🎯 Research Background

This tool is the result of research titled **"The Schrödinger's ESC1 Vulnerability"**, which investigates discrepancies in public tools when searching for ESC1 misconfigurations in Active Directory Certificate Services. The research explores how the same certificate template configuration can be classified simultaneously as vulnerable and non-vulnerable, depending on the tool used, mirroring Schrödinger's famous thought experiment where a cat exists in superposition until observed; during purple team exercises, conflicting results were observed in public tools' outputs used to assess ESC1 misconfigurations, and the misconfiguration appeared both exploitable and non-exploitable depending on the tool analyzing it.



## ✨ Features

### 🔐 Authentication Methods
- **Username/Password**: Standard domain authentication
- **NTLM Hash**: Pass-the-Hash support for security research
- **Interactive Password**: Secure password prompting

### 🔍 Enumeration Capabilities
- **Certificate Authorities**: Full CA discovery and configuration analysis
- **Certificate Templates**: Detailed template security analysis (LDAP-only)
- **Security Descriptors**: Binary parsing of Windows security descriptors
- **User Permissions**: SID resolution and group membership analysis
- **CA Permissions**: Enrollment rights and administrative permissions (via Impacket/DCERPC RRP)

### 📊 Output Options
- **Full Enumeration**: Comprehensive security analysis with detailed output
- **Filtered Results**: Show only enabled templates or vulnerable templates
- **Verbose Mode**: Detailed Access Control Entry (ACE) information
- **Color-Coded Output**: Easy-to-read terminal output with color coding

### 🎯 Vulnerability Detection
- **ESC1 Conditions**: Automatic detection of all ESC1 vulnerability conditions
- **Permission Analysis**: Deep analysis of DACL and enrollment rights
- **Template Validation**: Comprehensive template security validation
- **Risk Assessment**: Clear identification of potentially vulnerable templates

**Note**: CA enrollment permissions are recorded when available, but they are not required to flag a template as "potentially vulnerable". Confirm CA enroll rights on the CA to validate exploitation.

## 🚀 Installation

### Prerequisites

- **Python 3.8+**
- **Active Directory Environment** (for testing)
- **Network Access** to Domain Controllers

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/esc1_scanner.git
   cd esc1_scanner
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On Linux/macOS
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```



## 📖 Usage

### Basic Usage

```bash
# Basic enumeration
python esc1_scanner.py -u username@domain.com -p password

# With specific CA
python esc1_scanner.py -u username@domain.com -p password -c "CA-NAME"

# With specific template
python esc1_scanner.py -u username@domain.com -p password -t "Template-Name"

# Pass-the-Hash authentication
python esc1_scanner.py -u username@domain.com -n NTLM_HASH
```

### Advanced Options

```bash
# Only show enabled templates
python esc1_scanner.py -u username@domain.com -p password --enabled

# Only show vulnerable templates
python esc1_scanner.py -u username@domain.com -p password --vulnerable

# Verbose output with detailed ACE information
python esc1_scanner.py -u username@domain.com -p password --verbose

# Specify domain controller IP
python esc1_scanner.py -u username@domain.com -p password --dc_ip 192.168.1.10

# Interactive password prompt
python esc1_scanner.py -u username@domain.com -P
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-u, --user` | User in format username@domain.com | Yes |
| `-p, --password` | Password for authentication | No* |
| `-P` | Interactive password prompt | No* |
| `-n, --ntlm` | NTLM hash for Pass-the-Hash | No* |
| `-c, --ca` | Specific CA name to target | No |
| `-t, --template` | Specific template name to target | No |
| `--dc_ip` | Domain controller IP address | No |
| `--enabled` | Show only enabled templates | No |
| `--vulnerable` | Show only vulnerable templates | No |
| `--verbose` | Detailed ACE information | No |

*One authentication method is required

## 📝 Examples

### Example 1: Basic Enumeration

```bash
python esc1_scanner.py -u john.doe@contoso.com -p MyPassword123
```

**Output:**
```
[*] Resolving contoso.com...
[+] Resolved contoso.com to 192.168.1.10

[*] Establishing LDAP connection as john.doe...
[+] Successfully established LDAP connection

[+] Found 1 certification authority:
   Contoso-CA

[+] Found 15 certificate templates:
   User
   Machine
   DomainController
   ...

[+] Enumeration output:

Certification Authorities:
1
  CA Name -> Contoso-CA
  CA DNS -> ca.contoso.com
  CA Permissions
    0x00000200 Enroll -> Authorized to request certificates from the CA
      contoso\john.doe (S-1-5-21-...)

Certificate Templates:
1
  Template Name -> User
  CAs -> Contoso-CA
  Enrollment Flags -> 0x00000020
    AUTO_ENROLLMENT: Allow clients to perform autoenrollment for the specified template
  Certificate Name Flags -> 0x00000001
    ENROLLEE_SUPPLIES_SUBJECT: The subject name must be supplied by the enrollee
  Signatures Required -> 0
    Recovery agent signature is not required
  Extended Key Usages:
    1.3.6.1.5.5.7.3.2: Client Authentication
    EKUs enable authentication
  Security Descriptor Audit:
    Owner -> contoso\Domain Admins (S-1-5-21-...)
    Group -> contoso\Domain Users (S-1-5-21-...)
  DACL audit:
    ACL Revision -> 4 (Supports basic, compound and object ACE types)
    ACE Count -> 3
    ACE 1:
      SID -> contoso\Authenticated Users (S-1-5-11)
      Type -> ACCESS_ALLOWED_OBJECT_ACE (Grants access to a resource with an object type)
      Access Mask -> 0x00000100
      Object GUID -> 0e10c968-78fb-11d2-90d4-00c04f79dc55
      ACE grants enrollment permissions to low privileged SID
```

### Example 2: Vulnerability-Focused Scan

```bash
python esc1_scanner.py -u john.doe@contoso.com -p MyPassword123 --vulnerable
```

**Output:**
```
[+] Found 1 potentially vulnerable template:
   UserTemplate
     Potentially vulnerable to ESC1 (check CA permissions to confirm if low-priv users with enrollment permissions can request templates)
```

## 🔧 Technical Details

### Architecture

The tool follows a modular architecture:

1. **Authentication Layer**: LDAP3 library for Active Directory connectivity
2. **Enumeration Engine**: Comprehensive AD object discovery
3. **Security Parser**: Binary parsing of Windows security descriptors
4. **Vulnerability Analyzer**: ESC1 condition validation
5. **Output Formatter**: Color-coded terminal output

### Security Descriptor Analysis

The tool performs deep analysis of Windows security descriptors:

- **Binary Parsing**: Direct parsing of security descriptor bytes
- **SID Resolution**: Conversion of binary SIDs to readable format
- **DACL Analysis**: Access Control Entry (ACE) interpretation
- **Permission Mapping**: Translation of access masks to human-readable rights



## ⚠️ Security Considerations

### Ethical Usage

This tool is designed for **security research and authorized penetration testing**. Users must:

- **Obtain Proper Authorization**: Only use on systems you own or have explicit permission to test
- **Follow Responsible Disclosure**: Report vulnerabilities to system owners
- **Respect Privacy**: Do not access or disclose sensitive information
- **Comply with Laws**: Ensure usage complies with local and international laws



### Limitations

- **Network Access Required**: Requires connectivity to Domain Controllers
- **Authentication Required**: Valid domain credentials needed
- **Windows-Specific**: Designed for Active Directory environments
- **Research Tool**: Not intended for production security monitoring

### Detection/EDR Considerations

- **Template and DACL enumeration**: Performed via LDAP (`ldap3`) only. Operations are read-only queries against AD objects/attributes and, in typical environments, have a low likelihood of triggering EDR/network alerts.
- **CA permissions enumeration**: Performed via Impacket over DCERPC/`RRP` (Remote Registry) on `\\\\PIPE\\winreg`. These RPC interactions are commonly monitored and may trigger alerts. Remote Registry might not be enabled in some environments. The scanner handles failures gracefully and proceeds without CA permissions.
- **Classification behavior**: Templates are flagged as "potentially vulnerable" based on template-centric checks plus DACL analysis. CA enrollment permissions are recorded when available but are not required for the flag; confirm CA enroll rights on the CA to validate exploitation.

## 🤝 Contributing

We welcome contributions from the security research community!

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**: Follow the coding standards
4. **Test your changes**: Ensure all tests pass
5. **Submit a pull request**: Include detailed description of changes

### Development Guidelines

- **Code Style**: Follow PEP 8 standards
- **Documentation**: Add docstrings for new functions
- **Testing**: Include tests for new features
- **Security**: Review security implications of changes

### Research Collaboration

We encourage collaboration on Active Directory security research:

- **Share Findings**: Submit research papers and presentations
- **Improve Detection**: Help enhance vulnerability detection algorithms
- **Expand Coverage**: Add support for additional AD security scenarios

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.



## 📚 References

- [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [GitHub - GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GitHub - GhostPack/PSPKIAudit](https://github.com/GhostPack/PSPKIAudit)
- [GitHub - jakehildreth/Locksmith](https://github.com/jakehildreth/Locksmith)
- [GitHub - ly4k/Certipy](https://github.com/ly4k/Certipy)
- [MS-ADTS: Active Directory Technical Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
- [MS-CRTD: Certificate Templates Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/4c6950e4-1dc2-4ae3-98c3-b8919bb73822)
- [MS-DTYP: Windows Data Types](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/cca27429-5689-4a16-b2b4-9325d93e4ba2)
- [MS-WCCE: Windows Client Certificate Enrollment Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/446a0fca-7f27-4436-965d-191635518466)

---

**Disclaimer**: This tool is for educational and authorized security research purposes only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before use. 