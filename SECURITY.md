# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in this toolkit, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email asarewilliam0@gmail.com with:

1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if you have one)

We will acknowledge receipt within 48 hours and provide an initial assessment within 5 business days.

## Scope

This toolkit processes compliance data, OSCAL documents, and optionally connects to cloud provider APIs. Security concerns include:

- Credential exposure in configuration files or logs
- OSCAL document injection or manipulation
- Insecure handling of vulnerability scan data
- Cloud API credential management

## Security practices for users

- Never commit `cloud-api-config.yaml` with real credentials. Use the `.example` template and set credentials via environment variables.
- Review evidence collection scripts before running them against production cloud accounts.
- Store vulnerability scan results and POA&M data securely; they contain sensitive information about your security posture.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.x.x   | ✅ Current development |
