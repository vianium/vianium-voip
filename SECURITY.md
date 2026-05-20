# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in this repository, please do not
open a public issue. Report it privately so it can be addressed before
disclosure.

## How to report

Send an email to [hello@angelcareaga.com](mailto:hello@angelcareaga.com)
with the subject line:

```text
[SECURITY] <repo-name>: <one-line summary>
```

Include:

- Description of the vulnerability and its impact.
- Steps to reproduce, including proof of concept if available.
- Affected versions, commits, or files.
- Suggested remediation, if any.
- Whether you want to be credited in the fix announcement.

You may also use GitHub private vulnerability reporting if it is enabled for
this repository.

## What to expect

- Acknowledgement within 72 hours of receipt.
- Triage and assessment within 7 days.
- Coordinated disclosure after a fix is available.

Expected fix timelines:

| Severity | Target |
|---|---|
| Critical | 14 days |
| High | 30 days |
| Medium / Low | Next scheduled release |

## Scope

In scope:

- Source code in this repository.
- Default build configurations and declared dependencies.

Out of scope:

- Third-party vendored code. Report those issues upstream.
- Issues already addressed in `main`.
- Speculative reports without practical impact.

## Supported versions

| Version | Supported |
|---|---|
| Latest `main` | Yes |
| Latest released minor | Yes |
| Older releases | No, upgrade required |

## Credits

Reporters who follow this policy and consent to attribution will be credited
in the advisory and in [AUTHORS.md](AUTHORS.md) under "Security researchers".
