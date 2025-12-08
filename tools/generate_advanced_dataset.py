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
        "Dear User, Your account has been suspended due to suspicious activity. "
        "Click {link} to verify.",
        "URGENT: Verify your identity immediately or access will be revoked. {link}",
        "Congratulations! You've won a {item} value at ${price}. " "Claim here: {link}",
        "Invoice #{id} is overdue. Please pay immediately via this secure "
        "portal: {link}",
        "HR Update: Review the new salary structure attached. Login required.",
        "Security Alert: A new device signed in from {location}. "
        "If this wasn't you, secure data here: {link}",
        "CEO Request: I need you to handle a wire transfer of ${amount} ASAP. Confidential.",
        "Your package delivery failed. Reschedule delivery here: {link} within 24 hours.",
        "Subscription payment failed for Netflix. Update payment info: {link}",
        "Your password for Microsoft 365 expires today. Renew now: {link}",
        "Tax Refund Notification: You have a pending refund of ${amount}. Claim at {link}.",
        "Unusual sign-in detected from {location} on your {item}. Is this you?",
        "Final Warning: Your storage is full. Upgrade now or lose files: {link}",
        "Exclusive Deal: Get 90% off on {item} today only! Buy now: {link}",
        "Payment Confirmation: You sent ${amount} to {location}. Cancel if unauthorized: {link}",
        "Action Required: Your banking profile needs an update. Visit {link}",
        "IT Support: Please install the attached security patch immediately.",
        "Voicemail: You missed a call from HR. Listen here: {link}",
        "Charity Donation: verify your contribution of ${amount} to avoid tax penalties.",
        "Account Hacked: We detected malware. Download scanner: {link}",
    ],
    "safe": [
        "Hi team, Here are the minutes from today's meeting. Let me know if I missed anything.",
        "Just checking in on the status of the Q3 project timeline.",
        "The potluck is scheduled for Friday at 12 PM. Don't forget to bring a dish!",
        "Please find the attached quarterly report for your review.",
        "Reminder: Please submit your timesheets by end of day Friday.",
        "Welcome to the team! Here is your onboarding documentation.",
        "Can we reschedule our 1:1 to next Tuesday at 2 PM?",
        "Happy Birthday! Hope you have a great day.",
        "The office will be closed on Monday for the holiday.",
        "Thanks for the update. Looks good to proceed.",
        "The server maintenance is scheduled for Sunday at 3 AM.",
        "Can you send me the latest slide deck for the presentation?",
        "Lunch is in the breakroom. Pizza and soda provided!",
        "Don't forget to enroll in benefits by the deadline.",
        "Great job on closing that deal yesterday!",
        "I'll be out of office next week for vacation.",
        "Can verifying the integration test results today?",
        "Please update the Jira ticket with your latest findings.",
        "The client meeting moved to Zoom. Here is the link.",
        "Let's sync up on the marketing strategy tomorrow morning.",
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
            print("Warning: GEMINI_API_KEY not found. Using template engine only.")
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
