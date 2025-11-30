"""
Heuristics Module
Implements pattern-matching and evaluation logic for detecting phishing.
"""

import re
from typing import Dict, List, Tuple

from src.config import (
    HEURISTIC_WEIGHTS,
    SUSPICIOUS_EXTENSIONS,
    SUSPICIOUS_TLDS,
    URGENT_KEYWORDS,
    MAX_URL_LENGTH,
)


class PhishingHeuristics:
    """
    Evaluates emails against various heuristics to detect phishing patterns.
    """

    def __init__(self):
        """Initialize heuristics evaluator."""
        self.findings = []
        self.score = 0

    def evaluate(self, email_data: Dict) -> Tuple[int, List[Dict]]:
        """
        Evaluate email data against all heuristics.

        Args:
            email_data: Parsed email data from EmailParser

        Returns:
            Tuple of (score, findings_list)
        """
        self.findings = []
        self.score = 0

        # Run all heuristics
        self._check_sender_domain_mismatch(email_data)
        self._check_url_domain_mismatch(email_data)
        self._check_url_obfuscation(email_data)
        self._check_suspicious_attachments(email_data)
        self._check_header_anomalies(email_data)
        self._check_urgent_language(email_data)
        self._check_suspicious_tlds(email_data)
        self._check_ip_based_urls(email_data)

        return self.score, self.findings

    def _add_finding(
        self,
        heuristic_name: str,
        severity: str,
        description: str,
        details: Dict = None,
    ):
        """
        Add a finding to the results.

        Args:
            heuristic_name: Name of the heuristic (for weighting)
            severity: "LOW", "MEDIUM", "HIGH"
            description: Human-readable description
            details: Additional details dictionary
        """
        weight = HEURISTIC_WEIGHTS.get(heuristic_name, 5)

        # Adjust weight by severity
        severity_multiplier = {"LOW": 0.5, "MEDIUM": 1.0, "HIGH": 1.5}
        adjusted_weight = weight * severity_multiplier.get(severity, 1.0)

        self.score = min(100, self.score + adjusted_weight)

        finding = {
            "heuristic": heuristic_name,
            "severity": severity,
            "description": description,
            "weight": weight,
            "adjusted_weight": adjusted_weight,
        }

        if details:
            finding["details"] = details

        self.findings.append(finding)

    def _check_sender_domain_mismatch(self, email_data: Dict):
        """Check if sender domain matches the display name."""
        sender = email_data.get("sender", "")

        if not sender:
            self._add_finding(
                "sender_domain_mismatch",
                "HIGH",
                "No sender information found in email headers",
            )
            return

        # Extract domain from sender email
        try:
            domain = sender.split("@")[1].lower() if "@" in sender else ""
        except IndexError:
            self._add_finding(
                "sender_domain_mismatch",
                "HIGH",
                f"Invalid sender format: {sender}",
            )
            return

        # Check if domain looks suspicious (too short, numbers at end, etc.)
        if self._is_suspicious_domain(domain):
            self._add_finding(
                "sender_domain_mismatch",
                "MEDIUM",
                f"Suspicious domain pattern: {domain}",
                {"domain": domain},
            )

    def _check_url_domain_mismatch(self, email_data: Dict):
        """Check for mismatches between URL domain and displayed text."""
        urls = email_data.get("urls", [])
        sender = email_data.get("sender", "")

        for url_obj in urls:
            url = url_obj.get("url", "")
            domain = url_obj.get("domain", "")
            displayed_text = url_obj.get("displayed_text", "")

            if displayed_text:
                # Check if displayed text contains a different domain
                displayed_domain_match = re.search(
                    r"([a-z0-9][a-z0-9-]*\.)+[a-z0-9-]+",
                    displayed_text,
                    re.IGNORECASE
                )

                if displayed_domain_match:
                    displayed_domain = displayed_domain_match.group().lower()
                    if displayed_domain != domain and not self._is_subdomain(
                        displayed_domain, domain
                    ):
                        self._add_finding(
                            "url_mismatch_with_text",
                            "HIGH",
                            f"URL domain mismatch: displayed "
                            f"'{displayed_domain}' but links to '{domain}'",
                            {
                                "displayed": displayed_domain,
                                "actual": domain,
                                "url": url,
                            },
                        )

            # Check if URL domain matches sender domain
            if sender and "@" in sender:
                sender_domain = sender.split("@")[1].lower()
                if (
                    domain
                    and domain != sender_domain
                    and not self._is_subdomain(domain, sender_domain)
                ):
                    self._add_finding(
                        "url_mismatch_with_text",
                        "MEDIUM",
                        "URL domain doesn't match sender domain",
                        {"sender_domain": sender_domain, "url_domain": domain},
                    )

    def _check_url_obfuscation(self, email_data: Dict):
        """Check for obfuscated or suspicious URL patterns."""
        urls = email_data.get("urls", [])

        for url_obj in urls:
            url = url_obj.get("url", "")
            domain = url_obj.get("domain", "")

            # Check URL length
            if len(url) > MAX_URL_LENGTH:
                self._add_finding(
                    "url_obfuscation",
                    "MEDIUM",
                    f"Unusually long URL ({len(url)} chars) "
                    f"- may indicate obfuscation",
                    {
                        "url_length": len(url),
                        "url": url[:100] + "...",
                    },
                )

            # Check for URL shorteners
            shorteners = [
                "bit.ly",
                "tinyurl.com",
                "short.url",
                "ow.ly",
                "goo.gl",
            ]
            if any(
                shortener in domain for shortener in shorteners
            ):
                self._add_finding(
                    "url_obfuscation",
                    "HIGH",
                    f"Shortened URL detected: {domain} "
                    f"- destination is hidden",
                    {"url": url, "domain": domain},
                )

            # Check for hex-encoded or base64-like patterns in domain
            if re.search(
                r"%[0-9a-f]{2}", url, re.IGNORECASE
            ):
                self._add_finding(
                    "url_obfuscation",
                    "HIGH",
                    "URL contains hex-encoded characters "
                    "(obfuscation technique)",
                    {"url": url},
                )

            # Check for excessive subdomains (typosquatting)
            subdomain_count = (
                domain.count(".") if domain else 0
            )
            if subdomain_count > 3:
                self._add_finding(
                    "url_obfuscation",
                    "MEDIUM",
                    f"Excessive subdomains detected in URL "
                    f"({subdomain_count})",
                    {"domain": domain},
                )

    def _check_suspicious_attachments(self, email_data: Dict):
        """Check for suspicious file attachments."""
        attachments = email_data.get("attachments", [])

        if not attachments:
            return

        for attachment in attachments:
            filename = attachment.get("filename", "").lower()
            content_type = attachment.get("content_type", "").lower()

            # Check file extension
            for ext in SUSPICIOUS_EXTENSIONS:
                if filename.endswith(ext):
                    self._add_finding(
                        "suspicious_attachment",
                        "HIGH",
                        f"Suspicious file attachment: {filename}",
                        {
                            "filename": filename,
                            "extension": ext,
                            "content_type": content_type,
                        },
                    )
                    break

            # Check for double extensions
            if re.search(r"\.(\w+)\.(\w+)$", filename):
                self._add_finding(
                    "suspicious_attachment",
                    "HIGH",
                    f"Double extension detected: {filename}",
                    {"filename": filename},
                )

            # Check for suspicious content-type mismatch
            if content_type.startswith("application/") and not any(
                content_type.endswith(ext.strip("."))
                for ext in SUSPICIOUS_EXTENSIONS
            ):
                pass  # This is normal for most application files

    def _check_header_anomalies(self, email_data: Dict):
        """Check for anomalies in email headers."""
        headers = email_data.get("headers", {})
        sender = email_data.get("sender", "")
        reply_to = email_data.get("reply_to", "")

        # Check if Reply-To differs from From
        if reply_to and sender and reply_to.lower() != sender.lower():
            self._add_finding(
                "header_anomalies",
                "MEDIUM",
                "Reply-To address differs from From address",
                {"from": sender, "reply_to": reply_to},
            )

        # Check for missing or suspicious headers
        suspicious_header_absence = ["Date", "Message-ID"]
        for header in suspicious_header_absence:
            if header not in headers or not headers[header]:
                self._add_finding(
                    "header_anomalies",
                    "LOW",
                    f"Missing or empty header: {header}",
                    {"header": header},
                )

    def _check_urgent_language(self, email_data: Dict):
        """Check for urgent/threatening language in subject and body."""
        subject = email_data.get("subject", "").lower()
        body = email_data.get("body", "").lower()

        content = subject + " " + body

        # Count urgent keywords
        keyword_count = 0
        matched_keywords = []

        for keyword in URGENT_KEYWORDS:
            count = content.count(keyword.lower())
            if count > 0:
                keyword_count += count
                matched_keywords.append(keyword)

        if keyword_count >= 3:
            unique_keywords = list(set(matched_keywords))[:5]
            self._add_finding(
                "urgent_language",
                "MEDIUM",
                f"Multiple urgent/threatening keywords detected: "
                f"{', '.join(unique_keywords)}",
                {
                    "keyword_count": keyword_count,
                    "keywords": matched_keywords[:5],
                },
            )
        elif keyword_count >= 1:
            unique_keywords = list(set(matched_keywords))
            self._add_finding(
                "urgent_language",
                "LOW",
                f"Urgent language detected: {', '.join(unique_keywords)}",
                {"keywords": matched_keywords},
            )

    def _check_suspicious_tlds(self, email_data: Dict):
        """Check for suspicious top-level domains."""
        urls = email_data.get("urls", [])
        sender = email_data.get("sender", "")

        # Check sender domain TLD
        if sender and "@" in sender:
            domain = sender.split("@")[1].lower()
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    self._add_finding(
                        "suspicious_tld",
                        "MEDIUM",
                        f"Sender uses suspicious TLD: {tld}",
                        {"domain": domain, "tld": tld},
                    )

        # Check URL TLDs
        for url_obj in urls:
            domain = url_obj.get("domain", "").lower()
            for tld in SUSPICIOUS_TLDS:
                if domain.endswith(tld):
                    self._add_finding(
                        "suspicious_tld",
                        "MEDIUM",
                        f"URL contains suspicious TLD: {tld}",
                        {"domain": domain, "tld": tld},
                    )

    def _check_ip_based_urls(self, email_data: Dict):
        """Check for URLs using IP addresses instead of domain names."""
        urls = email_data.get("urls", [])

        for url_obj in urls:
            domain = url_obj.get("domain", "")
            url = url_obj.get("url", "")

            # Check if domain is an IP address
            ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$"
            if re.match(ip_pattern, domain):
                self._add_finding(
                    "ip_based_url",
                    "HIGH",
                    f"URL uses IP address instead of domain name: {domain}",
                    {"url": url, "ip": domain},
                )

    def _is_suspicious_domain(self, domain: str) -> bool:
        """
        Check if a domain has suspicious characteristics.

        Args:
            domain: Domain name to check

        Returns:
            True if domain is suspicious, False otherwise
        """
        if not domain or len(domain) < 5:
            return True

        # Check for numbers at the end of domain
        if re.search(r"-\d+\.|^\d+-", domain):
            return True

        # Check for excessive hyphens
        if domain.count("-") > 2:
            return True

        # Check for similar-looking characters (homoglyphs)
        homoglyph_patterns = [
            r"0o|O0",  # Zero and O
            r"1l|l1",  # One and l
        ]
        for pattern in homoglyph_patterns:
            if re.search(pattern, domain):
                return True

        return False

    def _is_subdomain(self, domain1: str, domain2: str) -> bool:
        """
        Check if domain1 is a subdomain of domain2.

        Args:
            domain1: Potential subdomain
            domain2: Potential parent domain

        Returns:
            True if domain1 is a subdomain of domain2
        """
        domain1_lower = domain1.lower()
        domain2_lower = domain2.lower()

        return domain1_lower == domain2_lower or domain1_lower.endswith(
            "." + domain2_lower
        )
