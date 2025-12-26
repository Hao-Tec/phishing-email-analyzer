## 2024-05-23 - SSRF Protection in URL Scraper
**Vulnerability:** The `URLScraper` class in `src/url_scraper.py` was vulnerable to Server-Side Request Forgery (SSRF) because it directly fetched URLs using `requests.get` without validating the destination IP address. This could allow attackers to access internal network resources (e.g., localhost, private IPs, cloud metadata services) by supplying a malicious URL.
**Learning:** Standard HTTP libraries like `requests` do not automatically protect against SSRF. When fetching user-provided URLs, it is critical to resolve the DNS hostname to an IP address and validate that the IP is not private, loopback, or reserved before making the connection. Furthermore, redirects must be handled manually to ensure that the redirect target is also validated, as an attacker could redirect a valid public URL to an internal resource.
**Prevention:**
1.  Parse the URL to extract the hostname.
2.  Resolve the hostname to an IP address using `socket.getaddrinfo`.
3.  Check if the IP is private, loopback, link-local, reserved, or multicast using `ipaddress`.
4.  If the IP is safe, proceed with the request.
5.  Disable automatic redirects (`allow_redirects=False`) and implement a loop to handle redirects manually, repeating the validation step for each new location.

## 2025-12-26 - XSS in HTML Reports
**Vulnerability:** The `EmailReporter` in `src/reporter.py` generated HTML reports by directly embedding email metadata (Subject, Sender, etc.) and analysis findings into f-strings without sanitization. This allowed attackers to inject malicious scripts (XSS) into the report via crafted email headers.
**Learning:** Never trust input from emails when generating HTML reports. Even metadata like "Date" or "Sender" can be manipulated. Standard Python f-strings do not provide auto-escaping.
**Prevention:** Always use `html.escape()` on ALL variable content before embedding it into HTML templates, or use a templating engine (like Jinja2) that handles auto-escaping by default.
