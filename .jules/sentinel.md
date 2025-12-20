# Sentinel Journal

This journal records CRITICAL security learnings, vulnerabilities, and patterns specific to this codebase.

## 2024-05-24 - [SSRF Protection]
**Vulnerability:** The `URLScraper` was vulnerable to SSRF (Server-Side Request Forgery) because it followed redirects blindly, potentially allowing attackers to access internal network resources.
**Learning:** Checking the initial URL is not enough. Attackers can use redirects to bypass IP blacklists.
**Prevention:** We implemented manual redirect handling in `src/url_scraper.py`, checking the destination IP address against a blacklist (private, loopback, link-local) *before* following each redirect. We also disabled `allow_redirects` in the initial request.
