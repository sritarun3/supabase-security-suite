# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Supabase Security Suite seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Please DO NOT:
- Open a public GitHub issue for security vulnerabilities
- Share the vulnerability publicly before it has been addressed

### Please DO:
1. **Report privately** by creating a GitHub Security Advisory or emailing the maintainers
2. **Provide details** including:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)
3. **Wait for acknowledgment** - We aim to respond within 48 hours

## What to Expect

After you submit a report, here's what will happen:

1. **Acknowledgment** (within 48 hours): We'll confirm receipt of your vulnerability report
2. **Assessment** (within 7 days): We'll assess the severity and impact
3. **Fix Development** (timeline varies): We'll develop and test a fix
4. **Release** (as soon as ready): We'll release the patched version
5. **Disclosure** (after release): We'll publish a security advisory with credit to you (if desired)

## Security Best Practices for Users

When using Supabase Security Suite:

1. **Keep Updated**: Always use the latest version
2. **Secure Configuration**: 
   - Never commit `config.json` with real credentials
   - Use environment variables for sensitive data
   - Enable dashboard authentication in production
3. **API Keys**:
   - Rotate API keys regularly
   - Use read-only credentials where possible
   - Store keys in secure vaults (not in code)
4. **Network Security**:
   - Run scans from trusted networks
   - Use VPN when scanning production systems
   - Limit dashboard access with firewall rules
5. **Report Handling**:
   - Store reports securely
   - Encrypt reports containing sensitive data
   - Follow your organization's data handling policies

## Known Security Considerations

### Dashboard Security
- The dashboard is designed for internal use
- Enable authentication before exposing to networks
- Use HTTPS in production (reverse proxy recommended)
- Dashboard logs may contain sensitive information

### Scan Data
- Scans may detect and log sensitive information
- Ensure proper access controls on report storage
- Consider encrypting reports at rest
- Clean up old scan results regularly

### Database Connections
- Scanner requires database credentials for RLS checks
- Use read-only database accounts where possible
- Credentials are never logged or sent to external services

### AI Integration
- Code snippets are sent to AI providers for analysis
- Review AI provider privacy policies
- Consider data residency requirements
- Disable AI features if handling highly sensitive code

## Disclosure Policy

We follow coordinated vulnerability disclosure:

- We'll work with you to understand and address the issue
- We'll keep you informed of progress
- We'll credit you in the security advisory (unless you prefer to remain anonymous)
- We'll publish details only after a fix is available

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue.

## Hall of Fame

We recognize and thank security researchers who help keep our project secure:

<!-- Contributors will be listed here -->
- Coming soon...

Thank you for helping keep Supabase Security Suite and its users safe! 🔒

