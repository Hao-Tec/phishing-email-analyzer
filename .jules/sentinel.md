## 2025-12-17 - [SSRF Protection in Python]
**Vulnerability:** The `URLScraper` was vulnerable to Server-Side Request Forgery (SSRF) because it used `requests.get` directly on user-supplied URLs without validating the destination IP address. This could allow attackers to access internal services (like localhost) or cloud metadata (like `169.254.169.254`).
**Learning:** `requests` follows redirects by default and lacks a built-in "safe" mode to check IPs before connection. Validating the initial URL is insufficient because a redirect can point to a private IP. `socket.gethostbyname` is insufficient as it only returns IPv4; `socket.getaddrinfo` is needed for full coverage.
**Prevention:**
1. Validate the IP address of the initial URL to ensure it is not private, loopback, link-local, or reserved.
2. Disable automatic redirects (`allow_redirects=False`).
3. Manually handle redirects in a loop, validating the destination IP at each step.
4. Use `requests.Session` for efficiency and proper cleanup.
5. Explicitly check for `is_link_local` to protect cloud environments.
