"""
Analyzer Module
Orchestrates email parsing and phishing detection.
"""

from pathlib import Path
from typing import Dict, List

from src.email_parser import EmailParser
from src.heuristics import HeuristicAnalyzer
from src.config import (
    SCORE_THRESHOLD,
    HEURISTIC_WEIGHTS,
    PLATFORM_DOMAINS,
)
from src.llm_analyzer import LLMAnalyzer
from src.vt_scanner import VirusTotalScanner
from src.auth_validator import AuthValidator
from src.image_analyzer import ImageAnalyzer
from src.ml_analyzer import MLAnalyzer
from src.external_scanners import ExternalScanners
from src.url_scraper import URLScraper


class EmailAnalyzer:
    """
    Main analyzer that coordinates parsing and heuristics evaluation.
    """

    def __init__(self):
        """Initialize the analyzer."""
        self.parser = EmailParser()
        self.heuristics = HeuristicAnalyzer()
        self.llm_analyzer = LLMAnalyzer()
        self.vt_scanner = VirusTotalScanner()
        # New components
        self.auth_validator = AuthValidator()
        self.image_analyzer = ImageAnalyzer()
        self.ml_analyzer = MLAnalyzer()
        self.ml_analyzer = MLAnalyzer()
        self.external_scanners = ExternalScanners()
        self.url_scraper = URLScraper()

    def analyze_email(self, email_path: str) -> Dict:
        """
        Analyze a single email for phishing.

        Args:
            email_path: Path to email file

        Returns:
            Analysis results dictionary
        """
        # Parse email
        try:
            email_data = self.parser.parse_email(email_path)
        except Exception as e:
            return {"status": "error", "error": str(e), "file": email_path}

        return self._run_analysis(email_data, email_path)

    def analyze_email_from_string(self, email_string: str) -> Dict:
        """
        Analyze email from string content.

        Args:
            email_string: Email content as string

        Returns:
            Analysis results dictionary
        """
        # Parse email
        try:
            email_data = self.parser.parse_email_from_string(email_string)
        except Exception as e:
            return {"status": "error", "error": str(e)}

        return self._run_analysis(email_data, "string_input")

    def _run_analysis(self, email_data: Dict, source: str) -> Dict:
        """
        Common analysis logic for file and string inputs.
        """
        findings = []
        score = 0

        # 1. OCR Analysis (Extract text from images)
        ocr_text = ""
        if self.image_analyzer.enabled:
            ocr_text = self.image_analyzer.extract_text_from_images(
                email_data.get("attachments", [])
            )
            if ocr_text:
                email_data["ocr_text"] = ocr_text

        # 2. Evaluate with heuristics (Standard)
        h_score, h_findings = self.heuristics.analyze(email_data)
        score += h_score
        findings.extend(h_findings)

        # 3. Authentication Verification (DKIM/SPF/DMARC)
        if email_data.get("raw_content") and email_data.get("sender"):
            auth_results = self.auth_validator.validate(
                email_data["raw_content"],
                email_data["headers"],
                email_data["sender"],
            )

            # Map auth results to findings
            if auth_results.get("dkim_pass") is False:
                findings.append(
                    {
                        "heuristic": "auth_dkim_fail",
                        "severity": "HIGH",
                        "description": "DKIM verification failed",
                        "weight": HEURISTIC_WEIGHTS["auth_dkim_fail"],
                        "adjusted_weight": HEURISTIC_WEIGHTS["auth_dkim_fail"],
                    }
                )
                score += HEURISTIC_WEIGHTS["auth_dkim_fail"]

            if auth_results.get("spf_record_exists") is False:
                findings.append(
                    {
                        "heuristic": "auth_spf_fail",
                        "severity": "MEDIUM",
                        "description": "Sender domain missing SPF record",
                        "weight": HEURISTIC_WEIGHTS["auth_spf_fail"],
                        "adjusted_weight": HEURISTIC_WEIGHTS["auth_spf_fail"],
                    }
                )
                score += HEURISTIC_WEIGHTS["auth_spf_fail"]

        # 4. ML Analysis
        if self.ml_analyzer.enabled:
            # Combine body and OCR text for ML analysis
            ml_input_text = email_data.get("body", "")
            if email_data.get("ocr_text"):
                ml_input_text += (
                    "\n\n[OCR EXTRACTED CONTENT]\n" + email_data["ocr_text"]
                )

            ml_prob, ml_details = self.ml_analyzer.analyze(ml_input_text)
            if ml_prob > 0.7:
                findings.append(
                    {
                        "heuristic": "ml_confidence_high",
                        "severity": "HIGH",
                        "description": (
                            f"ML Model detected phishing pattern "
                            f"({ml_prob:.2f})"
                        ),
                        "weight": HEURISTIC_WEIGHTS["ml_confidence_high"],
                        "adjusted_weight": (
                            HEURISTIC_WEIGHTS["ml_confidence_high"] * ml_prob
                        ),
                        "details": ml_details,
                    }
                )
                score += HEURISTIC_WEIGHTS["ml_confidence_high"] * ml_prob

        # 5. External Scanners & VirusTotal
        urls = email_data.get("urls", [])

        # Prioritize scanning PLATFORM_DOMAINS to ensure they are safe
        # We want to use our limited external scans on these "trusted" links
        # that bypass other heuristics.
        sorted_urls = sorted(
            urls,
            key=lambda u: u.get("domain", "") in PLATFORM_DOMAINS,
            reverse=True,
        )

        scanned_urls_count = 0
        MAX_EXTERNAL_SCANS = 5

        for url_obj in sorted_urls:
            if scanned_urls_count >= MAX_EXTERNAL_SCANS:
                break

            url = url_obj.get("url")
            domain = url_obj.get("domain", "")
            is_platform_domain = domain in PLATFORM_DOMAINS

            # ML URL Analysis
            if self.ml_analyzer.enabled:
                url_prob = self.ml_analyzer.analyze_url(url)
                if url_prob > 0.8:
                    findings.append(
                        {
                            "heuristic": "url_ml_suspicious",
                            "severity": "HIGH",
                            "description": (
                                f"ML Model (URL) detected malicious pattern "
                                f"({url_prob:.2f}): {url}"
                            ),
                            "weight": 80,
                            "adjusted_weight": 80 * url_prob,
                            "details": {"url": url, "probability": url_prob},
                        }
                    )
                    score += 80 * url_prob

            # VirusTotal (Existing)
            vt_scan = self.vt_scanner.scan_url(url)

            # Check for missing API key warning on Platform
            if is_platform_domain and vt_scan.get("error") == (
                "No API key configured"
            ):
                findings.append(
                    {
                        "heuristic": "url_obfuscation",  # Fallback category
                        "severity": "LOW",
                        "description": (
                            f"Unverified Platform Link: {domain} "
                            "(Configure VirusTotal)"
                        ),
                        "weight": 10,
                        "adjusted_weight": 10,
                        "details": {"url": url, "domain": domain},
                    }
                )
                score += 10

            if vt_scan.get("malicious", 0) > 0:
                findings.append(
                    {
                        "heuristic": "virustotal_positive",
                        "severity": "CRITICAL",
                        "description": f"VirusTotal flagged URL: {url}",
                        "weight": 100,
                        "adjusted_weight": 100,
                        "details": vt_scan,
                    }
                )
                score = 100
                break  # Stop if critical

            # External DBs (PhishTank/Google)
            ext_scan = self.external_scanners.scan_url(url)
            if ext_scan.get("is_malicious"):
                findings.append(
                    {
                        "heuristic": "external_db_positive",
                        "severity": "CRITICAL",
                        "description": (
                            f"URL found in phishing database "
                            f"({', '.join(ext_scan['sources'])}): {url}"
                        ),
                        "weight": 100,
                        "adjusted_weight": 100,
                        "details": ext_scan,
                    }
                )
                score = 100
                break

            scanned_urls_count += 1

        # 5.1 Real-Time URL Content Scraping (Top URL only)
        # Fetch actual page content for the AI to "see" what the link is.
        scraped_content = {}
        if urls and self.url_scraper:
            # Pick the most relevant URL (first in sorted list)
            target_url = (
                sorted_urls[0].get("url")
                if sorted_urls else urls[0].get("url")
            )
            if target_url:
                scrape_result = self.url_scraper.scrape(target_url)
                if scrape_result:
                    scraped_content = scrape_result
                    email_data["url_content"] = scraped_content  # Pass to LLM

                    # Add finding for transparency
                    findings.append(
                        {
                            "heuristic": "url_scan_content",
                            "severity": "INFO",
                            "description": (
                                f"Scanned URL content: "
                                f"{scraped_content.get('title')}"
                            ),
                            "weight": 0,
                            "adjusted_weight": 0,
                            "details": {"title": scraped_content.get("title")},
                        }
                    )

        # 6. LLM Analysis (Existing - kept as is, but using augmented body)
        llm_data = {}
        if email_data.get("body") or email_data.get("ocr_text"):
            # Combine body and OCR text for LLM analysis
            llm_input_text = email_data.get("body", "")
            if email_data.get("ocr_text"):
                llm_input_text += (
                    "\n\n[OCR EXTRACTED CONTENT]\n" + email_data["ocr_text"]
                )

            # We skip if score is already critical to save tokens,
            # unless we want full report
            llm_score, llm_data = self.llm_analyzer.analyze(
                llm_input_text, url_content=scraped_content
            )

            # Update score if high risk
            # Update score if high risk
            is_high_risk = llm_data.get("risk_level") in ["HIGH", "CRITICAL"]
            # Only flag if LLM explicitly says it's risky.
            # We ignore raw score because LLM might return high
            # confidence for SAFE verdict.
            if is_high_risk:
                findings.append(
                    {
                        "heuristic": "llm_analysis",
                        "severity": "HIGH",
                        "description": "AI-detected suspicious content",
                        "weight": HEURISTIC_WEIGHTS["llm_analysis"],
                        "adjusted_weight": (
                            HEURISTIC_WEIGHTS["llm_analysis"] * llm_score
                        ),
                        "details": llm_data,
                    }
                )
                score += HEURISTIC_WEIGHTS["llm_analysis"] * llm_score

            # Transparency: Report AI findings even if SAFE
            elif llm_data:
                description = "AI Analysis: Content appears safe"
                if "error" in llm_data:
                    # Sanitize error for display (avoid huge quota logs)
                    err_msg = str(llm_data["error"])
                    if "429" in err_msg or "quota" in err_msg.lower():
                        description = "AI Analysis Unavailable"
                    else:
                        description = f"AI Analysis Failed: {err_msg[:50]}..."

                findings.append(
                    {
                        "heuristic": "llm_analysis",
                        "severity": "LOW",
                        "description": description,
                        "weight": 0,
                        "adjusted_weight": 0,
                        "details": llm_data,  # Keep full details debug obj
                    }
                )

        # 7. AI Veto / Score Damping
        # If AI is confident it's safe AND no critical external flags exists
        # dampen high scores caused by mechanical failures.
        has_critical_findings = any(
            f.get("severity") == "CRITICAL" for f in findings
        )

        if not has_critical_findings and llm_data:
            risk = llm_data.get("risk_level", "UNKNOWN")

            if risk == "SAFE":
                findings.append(
                    {
                        "heuristic": "ai_risk_adjustment",
                        "severity": "INFO",
                        "description": (
                            "Score capped (Safe Zone) by AI assessment."
                        ),
                        "weight": 0,
                        "adjusted_weight": 0,
                    }
                )
                score = min(score * 0.3, 25)

            elif risk == "LOW":
                findings.append(
                    {
                        "heuristic": "ai_risk_adjustment",
                        "severity": "INFO",
                        "description": (
                            "Score capped (Low Risk) by AI assessment."
                        ),
                        "weight": 0,
                        "adjusted_weight": 0,
                    }
                )
                # Allow minor infractions but cap at 55 (Top of Low Risk)
                score = min(score, 55)

        # Cap score
        score = min(100, score)

        # Determine risk level
        risk_level = self._determine_risk_level(score)

        return {
            "status": "success",
            "file": source if source != "string_input" else "Input String",
            "email_metadata": {
                "sender": email_data.get("sender", ""),
                "recipient": email_data.get("recipient", ""),
                "subject": email_data.get("subject", ""),
                "date": email_data.get("date", ""),
                "is_html": email_data.get("is_html", False),
            },
            "phishing_suspicion_score": score,
            "risk_level": risk_level,
            "findings": findings,
            "llm_analysis": llm_data if llm_data else None,
            "urls_detected": len(email_data.get("urls", [])),
            "attachments_detected": len(email_data.get("attachments", [])),
            "extracted_data": {
                "urls": email_data.get("urls", []),
                "attachments": email_data.get("attachments", []),
                "scraped_url": email_data.get("url_content", {}).get("url"),
            },
            "scan_summary": {
                "engines": [
                    "PhishTank",
                    "GoogleSafeBrowsing",
                    "VirusTotal",
                ],
                "critical_hits": [
                    f for f in findings if f.get("severity") == "CRITICAL"
                ],
                "scraped_url": email_data.get("url_content", {}).get(
                    "title", "N/A"
                ),
            },
        }

    def analyze_batch(self, email_folder: str) -> List[Dict]:
        """
        Analyze all email files in a folder.

        Args:
            email_folder: Path to folder containing email files

        Returns:
            List of analysis results
        """
        folder_path = Path(email_folder)

        if not folder_path.is_dir():
            raise ValueError(f"Invalid folder path: {email_folder}")

        results = []
        # Added .msg and .gz
        email_extensions = {".eml", ".txt", ".msg", ".gz"}

        for email_file in folder_path.iterdir():
            if (
                email_file.is_file()
                and email_file.suffix.lower() in email_extensions
            ):
                result = self.analyze_email(str(email_file))
                results.append(result)

        return results

    def _determine_risk_level(self, score: float) -> str:
        """
        Determine risk level based on score.

        Args:
            score: Phishing suspicion score (0-100)

        Returns:
            Risk level string
        """
        if score < SCORE_THRESHOLD["LOW_RISK"]:
            return "SAFE"
        elif score < SCORE_THRESHOLD["MEDIUM_RISK"]:
            return "LOW_RISK"
        elif score < SCORE_THRESHOLD["HIGH_RISK"]:
            return "MEDIUM_RISK"
        elif score < SCORE_THRESHOLD["CRITICAL"]:
            return "HIGH_RISK"
        else:
            return "CRITICAL"
            
