## 2024-05-23 - SSRF Protection in URL Scraper
**Vulnerability:** The `URLScraper` class in `src/url_scraper.py` was vulnerable to Server-Side Request Forgery (SSRF) because it directly fetched URLs using `requests.get` without validating the destination IP address. This could allow attackers to access internal network resources (e.g., localhost, private IPs, cloud metadata services) by supplying a malicious URL.
**Learning:** Standard HTTP libraries like `requests` do not automatically protect against SSRF. When fetching user-provided URLs, it is critical to resolve the DNS hostname to an IP address and validate that the IP is not private, loopback, or reserved before making the connection. Furthermore, redirects must be handled manually to ensure that the redirect target is also validated, as an attacker could redirect a valid public URL to an internal resource.
**Prevention:**
1.  Parse the URL to extract the hostname.
2.  Resolve the hostname to an IP address using `socket.getaddrinfo`.
3.  Check if the IP is private, loopback, link-local, reserved, or multicast using `ipaddress`.
4.  If the IP is safe, proceed with the request.
5.  Disable automatic redirects (`allow_redirects=False`) and implement a loop to handle redirects manually, repeating the validation step for each new location.
