## 2024-05-23 - SSRF Protection in URL Scraper
**Vulnerability:** The `URLScraper` class in `src/url_scraper.py` was vulnerable to Server-Side Request Forgery (SSRF) because it directly fetched URLs using `requests.get` without validating the destination IP address. This could allow attackers to access internal network resources (e.g., localhost, private IPs, cloud metadata services) by supplying a malicious URL.
**Learning:** Standard HTTP libraries like `requests` do not automatically protect against SSRF. When fetching user-provided URLs, it is critical to resolve the DNS hostname to an IP address and validate that the IP is not private, loopback, or reserved before making the connection. Furthermore, redirects must be handled manually to ensure that the redirect target is also validated, as an attacker could redirect a valid public URL to an internal resource.
**Prevention:**
1.  Parse the URL to extract the hostname.
2.  Resolve the hostname to an IP address using `socket.getaddrinfo`.
3.  Check if the IP is private, loopback, link-local, reserved, or multicast using `ipaddress`.
4.  If the IP is safe, proceed with the request.
5.  Disable automatic redirects (`allow_redirects=False`) and implement a loop to handle redirects manually, repeating the validation step for each new location.

## 2025-01-20 - Stored XSS in HTML Reports
**Vulnerability:** The `EmailReporter.generate_html_report` method in `src/reporter.py` was vulnerable to Stored Cross-Site Scripting (XSS). User-controlled metadata (Sender, Subject) and finding details were interpolated directly into the HTML report string using f-strings without prior escaping. An attacker could craft an email with a malicious subject like `<script>alert(1)</script>` which would be executed when an analyst viewed the generated HTML report.
**Learning:** Python f-strings do NOT automatically escape HTML characters. When generating HTML content programmatically, all user-supplied input must be explicitly passed through `html.escape()` before being inserted into the template. Do not rely on "display-only" contexts to be safe; any string rendered in a browser is a vector.
**Prevention:**
1.  Identify all sources of user input (metadata, file names, URLs, finding details).
2.  Import `html` module.
3.  Before interpolation, wrap the variable in `html.escape(str(variable))`.
4.  Example: `<span>{html.escape(subject)}</span>` instead of `<span>{subject}</span>`.
