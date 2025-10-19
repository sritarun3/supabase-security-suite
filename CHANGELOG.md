# Changelog

All notable changes to the Supabase Security Suite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker volume scanning with automatic detection
- AI-powered security recommendations via OpenAI/OpenRouter
- Enterprise dashboard with real-time scan monitoring
- Jira integration for ticket creation
- Compliance mapping (SOC2, HIPAA, ISO27001)
- Secure privilege elevation for Docker operations
- Interactive charts for vulnerability visualization
- Export functionality (JSON, Markdown, PDF)

### Changed
- Enhanced static analysis with improved pattern matching
- Upgraded runtime probes with better error handling
- Improved database security checks
- Streamlined CLI interface with better UX

### Fixed
- Resolved `track` function availability issues after privilege escalation
- Fixed chart rendering stability in dashboard
- Corrected Docker volume permission handling
- Improved error handling across all components

## [1.0.0] - 2025-01-13

### Added
- Initial release of Supabase Security Suite
- Static analysis engine with secret detection
- Semgrep integration for advanced pattern matching
- Runtime probes for live endpoint testing
- Database security validation
- Network port scanning with nmap
- Rich terminal output with progress tracking
- JSON and Markdown report generation
- CLI dashboard for terminal-based results viewing

### Security Features
- Service role key detection
- JWT secret validation
- CORS configuration analysis
- HTTP endpoint identification
- GraphQL introspection testing
- REST API accessibility checks
- PostgreSQL security validation
- Row Level Security (RLS) analysis

### Technical Implementation
- Python 3.9+ compatibility
- Virtual environment support
- Modular architecture
- Comprehensive error handling
- Configurable scan parameters
- Extensible plugin system