# Security

Do not report vulnerabilities through public issues when they include exploit
details, secrets, credential material, private infrastructure information, or
unredacted customer data.

For now, use GitHub private vulnerability reporting on the repository when
available, or contact the maintainer privately before publishing details.

Security-sensitive areas in this repository include:

- `irodori-secure-store`
- proxy and transport handling
- extension permissions and native module loading
- generated extension SDK contracts
- release packaging templates

Remove secrets from logs, tests, manifests, screenshots, and reproduction data.
