"""
Phishing Dataset Generator
A dual-engine tool to create a vast, high-quality dataset for ML training.
1. Gemini Engine: Generates sophisticated, context-aware samples.
2. Template Engine: Generates high-volume structural variations.
"""

import os
import json
import random
import sys
from pathlib import Path

# Add root to import src.config
sys.path.append(os.getcwd())

import google.generativeai as genai  # noqa: E402
from src.config import GENERATION_CONFIG, DATASET_PATH  # noqa: E402

# Template Data for Fallback Generation
TEMPLATES = {
    "phishing": [
        "Account suspended. Click {link}.",
        "Verify identity: {link}",
        "You won {item} value ${price}. Claim: {link}",
        "Invoice #{id} overdue. Pay: {link}",
        "Salary attached. Login.",
        "New device {location}. Secure: {link}",
        "Wire ${amount} ASAP.",
        "Delivery failed. Reschedule: {link}",
        "Netflix payment failed: {link}",
        "Password expires. Renew: {link}",
        "Refund ${amount}. Claim: {link}",
        "Sign-in {location}. You?",
        "Storage full. Upgrade: {link}",
        "90% off {item}. Buy: {link}",
        "Sent ${amount} to {location}. Cancel: {link}",
        "Update banking. Visit {link}",
        "Install security patch.",
        "Missed call HR: {link}",
        "Verify donation ${amount}.",
        "Malware detected. Scanner: {link}",
    ],
    "safe": [
        "Meeting minutes attached.",
        "Checking Q3 timeline.",
        "Potluck Friday 12PM.",
        "Quarterly report attached.",
        "Submit timesheets EOD.",
        "Onboarding docs attached.",
        "Reschedule 1:1?",
        "Happy Birthday!",
        "Office closed Monday.",
        "Looks good.",
        "Maintenance Sun 3AM.",
        "Send slides?",
        "Pizza in breakroom.",
        "Enroll benefits.",
        "Great job yesterday.",
        "OOO next week.",
        "Verify results?",
        "Update Jira.",
        "Zoom link attached.",
        "Marketing sync?",
    ],
}

VARS = {
    "link": [
        "http://bit.ly/secure",
        "http://login-verification.com",
        "http://secure-portal.net",
        "http://verify-identity.org",
        "http://cloud-storage.net/login",
    ],
    "item": [
        "iPhone 15",
        "Tesla Model S",
        "$1000 Gift Card",
        "Walmart Voucher",
        "MacBook Pro",
        "Samsung Galaxy",
        "Rolex Watch",
        "PlayStation 5",
    ],
    "price": ["1000", "500", "150", "2500", "99", "10"],
    "id": ["9982", "1123", "4451", "8821", "5501", "3392"],
    "location": [
        "Russia",
        "China",
        "Unknown IP",
        "Brazil",
        "Nigeria",
        "Kiev",
        "Dallas",
    ],
    "amount": ["5,000", "12,500", "45,000", "1,200", "550", "9,999"],
}


class DatasetGenerator:
    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY")
        self.dataset = []
        self.target_size = 1000  # Vast dataset size

        if self.api_key:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel("gemini-1.5-flash")
        else:
            print("Warning: GEMINI_API_KEY not found. " "Using template engine only.")
            self.model = None

    def _generate_via_gemini(self, count=10):
        """Generate samples using Gemini API."""
        if not self.model:
            return []

        print(f"Requesting {count} advanced samples from Gemini...")
        samples = []

        # We'll do it in batches of 5 to respect token limits/prompt structure
        prompts = [
            (GENERATION_CONFIG["phishing_prompt"], 1),
            (GENERATION_CONFIG["safe_prompt"], 0),
        ]

        for prompt_text, label in prompts:
            try:
                response = self.model.generate_content(prompt_text)
                text = response.text.replace("```json", "").replace("```", "").strip()
                data = json.loads(text)

                for item in data:
                    samples.append(
                        {
                            "text": item.get("text"),
                            "label": item.get("label", label),
                            "source": "gemini-ai",
                        }
                    )
            except Exception as e:
                print(f"Gemini generation failed: {e}")

        return samples

    def _generate_via_templates(self, count_per_type=50):
        """Generate samples using randomized templates."""
        print(f"Generating {count_per_type * 2} template samples...")
        samples = []

        # Generate Phishing
        for _ in range(count_per_type):
            tmpl = random.choice(TEMPLATES["phishing"])
            text = tmpl.format(
                link=random.choice(VARS["link"]),
                item=random.choice(VARS["item"]),
                price=random.choice(VARS["price"]),
                id=random.choice(VARS["id"]),
                location=random.choice(VARS["location"]),
                amount=random.choice(VARS["amount"]),
            )
            samples.append({"text": text, "label": 1, "source": "template-engine"})

        # Generate Safe
        for _ in range(count_per_type):
            tmpl = random.choice(TEMPLATES["safe"])
            samples.append({"text": tmpl, "label": 0, "source": "template-engine"})

        return samples

    def generate(self):
        """Main generation flow."""
        # 1. Try Gemini
        gemini_samples = self._generate_via_gemini()
        self.dataset.extend(gemini_samples)

        # 2. Fill rest with Templates
        remaining = self.target_size - len(self.dataset)
        if remaining > 0:
            template_samples = self._generate_via_templates(remaining // 2)
            self.dataset.extend(template_samples)

        # 3. Save
        self.save()

    def save(self):
        output_path = Path(DATASET_PATH)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(self.dataset, f, indent=2)

        print(f"Success! Generated {len(self.dataset)} samples to {output_path}")


if __name__ == "__main__":
    generator = DatasetGenerator()
    generator.generate()
