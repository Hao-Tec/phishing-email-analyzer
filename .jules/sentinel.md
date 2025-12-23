## 2025-05-25 - SSRF Protection Implementation
**Vulnerability:** The `URLScraper` was vulnerable to Server-Side Request Forgery (SSRF), allowing it to fetch content from internal IP addresses (e.g., `localhost`, `127.0.0.1`, `169.254.169.254`) and potentially bypass firewall restrictions.
**Learning:** `requests.get()` automatically follows redirects by default, which can be exploited to redirect a request from a safe public URL to an internal IP. Additionally, relying solely on `socket.gethostbyname` misses IPv6 addresses.
**Prevention:**
1.  **Resolve & Check:** Use `socket.getaddrinfo` to resolve *all* IPs (IPv4 & IPv6) for a hostname and verify they are not private/reserved using `ipaddress`.
2.  **Manual Redirects:** Disable automatic redirects (`allow_redirects=False`) and manually handle them in a loop.
3.  **Check Every Hop:** Validate the destination IP for *every* redirect in the chain, not just the initial URL.
4.  **Resolve Relative URLs:** Use `urllib.parse.urljoin` to correctly handle relative redirects (`Location: /login`) against the current URL context.
