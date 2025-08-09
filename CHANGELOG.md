# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of ESC1 Scanner
- Comprehensive ESC1 vulnerability detection
- Active Directory Certificate Services enumeration
- Security descriptor analysis and parsing
- Multiple authentication methods (username/password, NTLM hash)
- Color-coded terminal output
- Support for filtering results (enabled templates, vulnerable templates)
- Verbose mode for detailed ACE information
- Support for specific CA and template targeting

### Features
- **Authentication Methods**: Username/password, NTLM hash, interactive password
- **Enumeration Capabilities**: CA discovery, template analysis, security descriptor parsing
- **Output Options**: Full enumeration, filtered results, verbose mode, color-coded output
- **Vulnerability Detection**: Automatic ESC1 condition validation and risk assessment

### Technical Details
- Built with Python 3.8+
- Uses LDAP3 for Active Directory connectivity
- Implements binary parsing of Windows security descriptors
- Follows Microsoft's MS-CRTD, MS-WCCE, and MS-ADTS specifications
- Modular architecture with clear separation of concerns

### Research Context
- Based on "The Schrödinger's ESC1 Vulnerability" research
- Addresses discrepancies in public ESC1 detection tools
- Provides complementary auditing method for accurate vulnerability assessment

## [1.0.0] - 2024-12-19

### Added
- Initial public release
- Core ESC1 scanning functionality
- Research documentation and whitepaper integration

---

## Version History

- **v1.0.0**: Initial release with core ESC1 scanning capabilities
- **Unreleased**: Development version with ongoing improvements

## Contributing

When contributing to this project, please update this changelog with your changes following the format above. 