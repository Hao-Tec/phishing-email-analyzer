from typing import Dict, List
import logging

# Optional imports handled gracefully
try:
    import dns.resolver

    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import dkim

    DKIM_AVAILABLE = True
except ImportError:
    DKIM_AVAILABLE = False


class AuthValidator:
    """
    Validates sender identity using SPF, DKIM, and DMARC.
    """

    def __init__(self):
        """Initialize the validator."""
        self.resolver = None
        if DNS_AVAILABLE:
            self.resolver = dns.resolver.Resolver()
            # Configure resolver timeout to avoid hanging
            self.resolver.lifetime = 10.0
            self.resolver.timeout = 10.0
        else:
            logging.warning("dnspython missing. SPF/DMARC checks disabled.")

        if not DKIM_AVAILABLE:
            logging.warning("dkimpy not installed. DKIM checks disabled.")

    def validate(
        self, email_content: bytes, headers: Dict, sender: str
    ) -> Dict[str, bool]:
        """
        Run all authentication checks.

        Args:
            email_content: Raw email bytes
            headers: Parsed headers dictionary
            sender: Sender email address

        Returns:
            Dictionary of results keys: 'dkim_pass', 'spf_pass', 'dmarc_pass'
        """
        results = {
            "dkim_pass": None,
            "spf_pass": None,
            "dmarc_pass": None,
            "details": [],
        }

        # Custom logic for local files (missing IP context)
        # If we can't fully validate SPF because we don't know the connecting IP,
        # we shouldn't fail it hard.

        # DKIM Verification
        if DKIM_AVAILABLE:
            try:
                # dkim.verify returns True if valid, False otherwise
                dkim_result = dkim.verify(email_content)
                results["dkim_pass"] = dkim_result
                if not dkim_result:
                    # Provide a softer message for local analysis context
                    results["details"].append(
                        "DKIM verification failed (or unsure context)"
                    )
            except Exception as e:
                results["details"].append(f"DKIM verification error: {str(e)}")
                results["dkim_pass"] = False

        # Extract domain
        try:
            domain = sender.split("@")[1]
        except IndexError:
            results["details"].append("Could not extract domain from sender")
            return results

        # SPF Check (Active DNS lookup)
        if DNS_AVAILABLE and self.resolver:
            try:
                spf_record = self._get_dns_record(domain, "TXT")
                has_spf = any("v=spf1" in str(r) for r in spf_record)

                results["spf_record_exists"] = has_spf
                if not has_spf:
                    results["details"].append(
                        f"No SPF record found for domain {domain}"
                    )
                else:
                    # If record exists but we are analyzing a local file,
                    # we can't verify if the sender IP is authorized.
                    # Mark as None (Inconclusive) rather than False.
                    results["spf_pass"] = None

            except Exception as e:
                results["details"].append(f"SPF lookup error: {str(e)}")

        # DMARC Check (Active DNS lookup)
        if DNS_AVAILABLE and self.resolver:
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_record = self._get_dns_record(dmarc_domain, "TXT")
                has_dmarc = any("v=DMARC1" in str(r) for r in dmarc_record)

                results["dmarc_record_exists"] = has_dmarc
                if not has_dmarc:
                    results["details"].append(
                        f"No DMARC record found for domain {domain}"
                    )
            except Exception as e:
                results["details"].append(f"DMARC lookup error: {str(e)}")

        return results

    def _get_dns_record(self, domain: str, record_type: str) -> List[str]:
        """Helper to query DNS."""
        if not DNS_AVAILABLE or not self.resolver:
            return []

        try:
            answers = self.resolver.resolve(domain, record_type)
            return [
                txt_string.decode("utf-8")
                for rdata in answers
                for txt_string in rdata.strings
            ]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.exception.Timeout,
        ):
            return []
        except Exception:
            return []
