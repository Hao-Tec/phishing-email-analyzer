## 2024-05-23 - SSRF in URL Fetching
**Vulnerability:** Unrestricted URL fetching allowed access to internal network and metadata services (SSRF).
**Learning:** `requests` automatically follows redirects, which can bypass initial IP checks. Manual redirect handling is required to validate every hop.
**Prevention:** Always resolve and validate destination IP addresses before fetching. Disable auto-redirects and validate `Location` headers recursively.
