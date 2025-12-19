# fmt: off
"""
Heuristics Module
Implements rule-based checks for phishing detection.
"""

import re
import difflib
from typing import Dict, List, Tuple
from src.config import (
    HEURISTIC_WEIGHTS,
    MAX_URL_LENGTH,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_EXTENSIONS,
    PLATFORM_DOMAINS,
    WHITELIST_DOMAINS,
    TRUSTED_DOMAIN_GROUPS,
    EMAIL_INFRASTRUCTURE_DOMAINS,
)

# Pre-compile regexes for performance optimization
# Complex regex for extracting domain from displayed text
DISPLAYED_DOMAIN_PATTERN = (
    r"([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}"
)
DISPLAYED_DOMAIN_REGEX = re.compile(DISPLAYED_DOMAIN_PATTERN, re.IGNORECASE)

# Regex for detecting hex encoding in URLs
HEX_ENCODING_REGEX = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)

# Combined regex for urgency keywords
# Sort keywords by length descending to ensure longest match is found first
# in case of overlaps (though current list has no overlaps).
_sorted_keywords = sorted(SUSPICIOUS_KEYWORDS, key=len, reverse=True)
URGENCY_PATTERN = (
    r"\b(" + "|".join(re.escape(k) for k in _sorted_keywords) + r")\b"
)
# Text is lowercased before check, so we don't strictly need IGNORECASE.
URGENCY_REGEX = re.compile(URGENCY_PATTERN)

# Pre-compute trusted targets for doppelganger detection
TRUSTED_TARGETS = WHITELIST_DOMAINS.union(PLATFORM_DOMAINS)

# OPTIMIZATION: Pre-computed tuple for fast endswith checks
SUSPICIOUS_EXTENSIONS_TUPLE = tuple(SUSPICIOUS_EXTENSIONS)
# Pre-compute stripped extensions for content-type checks
SUSPICIOUS_CONTENT_TYPE_SUFFIXES = tuple(
    ext.lstrip(".") for ext in SUSPICIOUS_EXTENSIONS
)

# OPTIMIZATION: Module-level constant to avoid re-creation in loop
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "short.url",
    "ow.ly",
    "goo.gl",
]


class HeuristicAnalyzer:
    """
    Analyzes email content using heuristic rules.
    """

    def __init__(self):
        """Initialize the heuristic analyzer."""
        self.score = 0.0
        self.heuristic_scores = {}  # Track individual scores
        self.details = []

    def analyze(self, email_data: Dict) -> Tuple[float, List[Dict]]:
        """
        Run all heuristic checks and calculate a risk score.

        Args:
            email_data: Dictionary containing parsed email parts.

        Returns:
            Tuple (total_score, findings_list)
        """
        # Reset state per analysis
        self.score = 0.0
        self.heuristic_scores = {}
        self.details = []

        # Run checks
        self._check_urgency_keywords(email_data)
        self._check_ocr_content(email_data)
        self._check_link_mismatches(email_data)
        self._check_suspicious_attachments(email_data)
        self._check_sender_anomalies(email_data)
        self._check_url_obfuscation(email_data)
        self._check_header_anomalies(email_data)

        return self.score, self.details

    def _add_finding(
        self,
        heuristic_name: str,
        severity: str,
        description: str,
        context: Dict = None,
    ):
        """
        Add a finding and update the score, with logic to prevent excessive
        piling up.
        """
        raw_score_increase = HEURISTIC_WEIGHTS.get(heuristic_name, 0.0)
        current_type_score = self.heuristic_scores.get(heuristic_name, 0.0)

        # Cap the score contribution from a single heuristic type
        # e.g., don't let 10 "urgency" keywords add 10 * 10 points.
        # Max contribution per type is 3x the base weight.
        max_allowed = raw_score_increase * 3.0
        allowed_increase = max(0, max_allowed - current_type_score)
        actual_increase = min(raw_score_increase, allowed_increase)

        # Update scores
        self.heuristic_scores[heuristic_name] = current_type_score
        self.heuristic_scores[heuristic_name] += actual_increase
        self.score += actual_increase

        finding = {
            "heuristic": heuristic_name,
            "severity": severity,
            "description": description,
            "weight": raw_score_increase,
            "adjusted_weight": actual_increase,
        }
        if context:
            finding["context"] = context

        self.details.append(finding)

    def _check_urgency_keywords(self, email_data: Dict):
        """Check for urgency words in subject and body."""
        subject = email_data.get("subject", "").lower()
        body = email_data.get("body", "").lower()

        # Combine text for analysis
        full_text = f"{subject} {body}"

        # OPTIMIZATION: Use single regex pass for all keywords
        matches = set(URGENCY_REGEX.findall(full_text))
        for keyword in matches:
            self._add_finding(
                "urgent_language",
                "LOW",
                f"Suspicious keyword found: '{keyword}'",
            )

    def _check_ocr_content(self, email_data: Dict):
        """Check for suspicious content in OCR extracted text."""
        ocr_text = email_data.get("ocr_text", "").lower()
        if not ocr_text:
            return

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in ocr_text:
                self._add_finding(
                    "ocr_suspicious_content",
                    "MEDIUM",
                    f"Suspicious keyword detected in image text: '{keyword}'",
                    {"keyword": keyword},
                )

    def _is_subdomain(self, child: str, parent: str) -> bool:
        """Check if child is a subdomain of parent."""
        return child.endswith("." + parent) or child == parent

    def _is_trusted_ecosystem(
        self, sender_domain: str, link_domain: str
    ) -> bool:
        """
        Check if the link domain is part of the same trusted ecosystem
        as the sender (e.g., google.com -> drive.google.com,
        microsoft.com -> office.com).
        Uses config.TRUSTED_ECOSYSTEMS (simulated logic here)
        """
        # This prevents marking google.com links in a gmail email as suspicious
        if not sender_domain or not link_domain:
            return False

        # Simplified Logic:
        # If both domains share a root (e.g. google.com and drive.google.com)
        if (
            link_domain.endswith(sender_domain) or
            sender_domain.endswith(link_domain)
        ):
            return True

        # Check against configured trusted ecosystems
        for ecosystem_root, related_domains in TRUSTED_DOMAIN_GROUPS.items():
            # Check if sender is in this ecosystem
            sender_is_member = (
                self._is_subdomain(sender_domain, ecosystem_root)
                or any(
                    self._is_subdomain(sender_domain, d)
                    for d in related_domains
                )
            )

            if sender_is_member:
                # Check if link is also in this ecosystem
                if (
                    self._is_subdomain(link_domain, ecosystem_root)
                    or any(
                        self._is_subdomain(link_domain, d)
                        for d in related_domains
                    )
                ):
                    return True

        return False

    def _check_link_mismatches(self, email_data: Dict):
        """
        Check for:
        1. Mismatch between displayed text and actual URL.
        2. Mismatch between URL domain and Sender domain (if not a platform).
        """
        urls = email_data.get("urls", [])
        sender = email_data.get("sender", "")
        sender_domain = ""
        if "@" in sender:
            sender_domain = sender.split("@")[1].lower()

        for url_obj in urls:
            url = url_obj.get("url", "")
            domain = url_obj.get("domain", "")
            displayed_text = url_obj.get("text", "")

            # 1. Check Displayed Text Mismatch
            # Only if the displayed text looks like a URL/Domain
            if displayed_text and "." in displayed_text:
                # Extract domain from displayed text if possible
                # OPTIMIZATION: Use pre-compiled regex
                displayed_domain_match = DISPLAYED_DOMAIN_REGEX.search(
                    displayed_text
                )

                if displayed_domain_match:
                    displayed_domain = displayed_domain_match.group().lower()
                    self._display_domain_match_check(
                        domain, displayed_domain, url
                    )

                # 2. Check URL domain vs Sender Domain
                # Check if it's a subdomain of a trusted platform
                is_platform = False
                if domain in PLATFORM_DOMAINS:
                    is_platform = True
                else:
                    for p_domain in PLATFORM_DOMAINS:
                        if self._is_subdomain(domain, p_domain):
                            is_platform = True
                            break

                # Check for "Transparent Links"
                is_transparent = False
                if displayed_text:
                    disp_clean = (
                        displayed_text.lower()
                        .replace("https://", "")
                        .replace("http://", "")
                        .replace("www.", "")
                        .strip("/")
                    )
                    dom_clean = domain.lower().replace("www.", "")
                    if dom_clean in disp_clean or disp_clean in dom_clean:
                        is_transparent = True

                if (
                    domain
                    and domain != sender_domain
                    and not self._is_subdomain(domain, sender_domain)
                    and not self._is_trusted_ecosystem(sender_domain, domain)
                    and not is_platform
                    and not is_transparent
                ):
                    # Only flag if not whitelisted generic sender
                    if sender_domain not in WHITELIST_DOMAINS:
                        self._add_finding(
                            "url_mismatch_with_text",
                            "MEDIUM",
                            "URL domain doesn't match sender domain",
                            {
                                "sender_domain": sender_domain,
                                "url_domain": domain,
                            },
                        )

    def _display_domain_match_check(
        self, actual_domain: str, displayed_domain: str, url: str
    ):
        """Helper to check if displayed domain matches actual domain."""
        # Clean domains
        actual_clean = actual_domain.replace("www.", "")
        displayed_clean = displayed_domain.replace("www.", "")

        if actual_clean != displayed_clean and not self._is_subdomain(
            actual_clean, displayed_clean
        ):
            self._add_finding(
                "url_mismatch_with_text",
                "HIGH",
                (
                    f"Link displayed as '{displayed_domain}' but leads to "
                    f"'{actual_domain}'"
                ),
                {
                    "url": url,
                    "displayed": displayed_domain,
                    "actual": actual_domain,
                },
            )

    def _check_url_obfuscation(self, email_data: Dict):
        """Check for obfuscated or suspicious URL patterns."""
        urls = email_data.get("urls", [])
        sender = email_data.get("sender", "")
        sender_domain = ""
        if sender and "@" in sender:
            sender_domain = sender.split("@")[1].lower()

        for url_obj in urls:
            url = url_obj.get("url", "")
            domain = url_obj.get("domain", "")

            # Skip checks for trusted domains/ecosystems
            if self._is_trusted_ecosystem(sender_domain, domain):
                continue

            # Skip checks for known email infrastructure (tracking links)
            # These legitimately use very long URLs for click tracking
            is_email_infra = any(
                infra_domain in domain.lower()
                for infra_domain in EMAIL_INFRASTRUCTURE_DOMAINS
            )
            if is_email_infra:
                continue

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
            # OPTIMIZATION: Use module-level constant
            if any(shortener in domain for shortener in URL_SHORTENERS):
                self._add_finding(
                    "url_obfuscation",
                    "HIGH",
                    (
                        f"Shortened URL: {domain} "
                        f"- hidden dest"
                    ),
                    {"url": url, "domain": domain},
                )

            # Check for hex-encoded or base64-like patterns
            # in domain
            # OPTIMIZATION: Use pre-compiled regex
            if HEX_ENCODING_REGEX.search(url):
                self._add_finding(
                    "url_obfuscation",
                    "HIGH",
                    (
                        "URL contains hex-encoded characters "
                        "(obfuscation technique)"
                    ),
                    {"url": url},
                )

            # Check for excessive subdomains (typosquatting)
            # Trusted subdomains are exempt
            subdomain_count = domain.count(".") if domain else 0
            if subdomain_count > 3:
                self._add_finding(
                    "url_obfuscation",
                    "MEDIUM",
                    (
                        f"Excessive subdomains detected in URL "
                        f"({subdomain_count})"
                    ),
                    {"domain": domain},
                )

    def _check_suspicious_attachments(self, email_data: Dict):
        """Check for suspicious file attachments."""
        attachments = email_data.get("attachments", [])

        for att in attachments:
            filename = att.get("filename", "").lower()
            content_type = att.get("content_type", "").lower()

            # Check Extension
            # OPTIMIZATION: Use tuple for fast endswith check (C implementation)
            if filename.endswith(SUSPICIOUS_EXTENSIONS_TUPLE):
                self._add_finding(
                    "suspicious_attachment",
                    "HIGH",
                    f"Suspicious attachment extension: {filename}",
                    {"filename": filename},
                )

            # Check for suspicious content-type mismatch
            if content_type.startswith("application/"):
                # OPTIMIZATION: Use tuple for fast endswith check
                suspicious_ext = content_type.endswith(
                    SUSPICIOUS_CONTENT_TYPE_SUFFIXES
                )
                if not suspicious_ext:
                    pass  # This is normal for most files

    def _check_header_anomalies(self, email_data: Dict):
        """Check for anomalies in email headers."""
        # headers = email_data.get("headers", {}) # Unused
        sender = email_data.get("sender", "")
        reply_to = email_data.get("reply_to", "")

        # 1. Reply-To Mismatch
        if sender and reply_to:
            # Simple check: ignore friendly names, check email part
            sender_email = sender
            if "<" in sender:
                sender_email = sender.split("<")[1].strip(">")

            reply_to_email = reply_to
            if "<" in reply_to:
                reply_to_email = reply_to.split("<")[1].strip(">")

            if sender_email.lower() != reply_to_email.lower():
                self._add_finding(
                    "header_anomalies",
                    "MEDIUM",
                    "Reply-To address differs from Sender address",
                    {"sender": sender, "reply_to": reply_to},
                )

    def _check_sender_anomalies(self, email_data: Dict):
        """Check for anomalies in sender address."""
        sender = email_data.get("sender", "")
        if not sender:
            return

        # Check for free email providers asking for money/urgency (Contextual)
        # This is hard to do without NL, but we can flag high-risk
        # generic domains if other indicators are present.

        # Check for "doppelganger" domains (e.g. gmai1.com)
        if "@" in sender:
            sender_domain = sender.split("@")[1].lower()

            # Skip if sender domain is trusted
            if (
                sender_domain in WHITELIST_DOMAINS
                or sender_domain in PLATFORM_DOMAINS
            ):
                return

            # Skip if sender domain is a subdomain of trusted domains
            # Pre-compute the whitelist set once (avoid O(N) allocation
            # per email)
            if not hasattr(self, '_whitelist_set'):
                self._whitelist_set = \
                    WHITELIST_DOMAINS.union(PLATFORM_DOMAINS)
            for trusted in self._whitelist_set:
                if self._is_subdomain(sender_domain, trusted):
                    return

            # Check against trusted domains for similarity
            # OPTIMIZATION: Use pre-computed set and reused SequenceMatcher
            matcher = difflib.SequenceMatcher(None, b=sender_domain)
            len_s = len(sender_domain)

            for target in TRUSTED_TARGETS:
                # OPTIMIZATION: Quick check based on length and character set
                # ratio() is expensive (O(N*M)), so we filter first.
                # Max possible ratio is determined by lengths:
                # 2 * min_len / (len1 + len2) >= 0.85
                len_t = len(target)
                if len_s + len_t == 0:
                    continue
                if 2 * min(len_s, len_t) / (len_s + len_t) <= 0.85:
                    continue

                # Reuse matcher by setting sequence 1 (target)
                # Sequence 2 (sender) is cached in matcher
                matcher.set_seq1(target)

                # quick_ratio() is an upper bound on ratio()
                if matcher.quick_ratio() <= 0.85:
                    continue

                ratio = matcher.ratio()
                # Threshold for "doppelganger" detection (e.g. gmai1 vs gmail)
                if ratio > 0.85:
                    self._add_finding(
                        "doppelganger_domain",
                        "HIGH",
                        (
                            f"Sender domain '{sender_domain}' mimics "
                            f"legitimate domain '{target}'"
                        ),
                        {
                            "sender_domain": sender_domain,
                            "target_domain": target,
                            "similarity": ratio,
                        },
                    )
                    break  # Stop after first match to avoid duplicates
# fmt: on
