## 2024-05-23 - SSRF Protection in URL Scraper
**Vulnerability:** The `URLScraper` class in `src/url_scraper.py` was vulnerable to Server-Side Request Forgery (SSRF) because it directly fetched URLs using `requests.get` without validating the destination IP address. This could allow attackers to access internal network resources (e.g., localhost, private IPs, cloud metadata services) by supplying a malicious URL.
**Learning:** Standard HTTP libraries like `requests` do not automatically protect against SSRF. When fetching user-provided URLs, it is critical to resolve the DNS hostname to an IP address and validate that the IP is not private, loopback, or reserved before making the connection. Furthermore, redirects must be handled manually to ensure that the redirect target is also validated, as an attacker could redirect a valid public URL to an internal resource.
**Prevention:**
1.  Parse the URL to extract the hostname.
2.  Resolve the hostname to an IP address using `socket.getaddrinfo`.
3.  Check if the IP is private, loopback, link-local, reserved, or multicast using `ipaddress`.
4.  If the IP is safe, proceed with the request.
5.  Disable automatic redirects (`allow_redirects=False`) and implement a loop to handle redirects manually, repeating the validation step for each new location.

## 2024-05-24 - DoS Protection in Email Parser
**Vulnerability:** The `EmailParser` class in `src/email_parser.py` was vulnerable to Denial of Service (DoS) attacks via "zip bombs" or excessively large email files. It was reading the entire file content into memory using `f.read()` without any size limit, which could lead to memory exhaustion (OOM) and crash the application.
**Learning:** When processing file uploads or reading files that may be user-controlled (even indirectly), always enforce a maximum size limit. Python's `read()` method reads the entire file by default, which is dangerous for untrusted input. `gzip.open` also supports `read(size)`, allowing consistent protection for both compressed and plain files.
**Prevention:**
1.  Define a reasonable `MAX_EMAIL_SIZE` limit (e.g., 50MB) in configuration.
2.  Use `f.read(MAX_EMAIL_SIZE)` instead of `f.read()` in all file reading operations within the parser.
3.  Truncating the input is a safe fail-state for security analysis (better to analyze partial content than crash), though in production one might want to reject the file entirely if it exceeds the limit.
