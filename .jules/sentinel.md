## 2024-05-23 - SSRF Vulnerability in URL Scraper
**Vulnerability:** The `URLScraper` class blindly fetched any URL provided in an email using `requests.get()`. This allowed Server-Side Request Forgery (SSRF), where an attacker could probe internal network resources (localhost, private IPs, AWS metadata service) via the phishing analysis tool.
**Learning:** Security tools that interact with untrusted content (like URLs from phishing emails) are prime targets for attacks. `requests` handles DNS automatically, making it easy to accidentally connect to internal IPs if DNS rebinding or direct IP usage isn't blocked.
**Prevention:**
1.  **Resolve first:** Always resolve the hostname to an IP address before connecting.
2.  **Validate IP:** Check if the IP is in private, loopback, or reserved ranges (`ipaddress` library is great for this).
3.  **Handle Redirects:** Manually handle redirects to repeat the check for every hop. Standard `allow_redirects=True` is dangerous here because a safe domain can redirect to an unsafe one.
