import os
import email
from email.message import EmailMessage
from email.utils import formatdate

SAMPLES_DIR = "samples"


def save_email(filename, subject, from_addr, to_addr, body, attachments=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(body)

    if attachments:
        for att_name, att_data in attachments:
            msg.add_attachment(
                att_data,
                maintype="application",
                subtype="octet-stream",
                filename=att_name,
            )

    path = os.path.join(SAMPLES_DIR, filename)
    with open(path, "wb") as f:
        f.write(msg.as_bytes())
    print(f"Created: {path}")


def create_samples():
    os.makedirs(SAMPLES_DIR, exist_ok=True)

    # --- TOTALLY LEGIT SAMPLES (Aim for 0 findings) ---

    # 1. Team Lunch (Internal, simple, no links)
    save_email(
        "legit_1_lunch.eml",
        "Team Lunch on Friday?",
        "alice@company.com",
        "team@company.com",
        """Hi everyone,

Are we still on for lunch this Friday at typical place?
Let me know if we need to make a reservation.

Best,
Alice
""",
    )

    # 2. Meeting Notes (Safe domains, professional tone)
    save_email(
        "legit_2_notes.eml",
        "Notes from Q1 Sync",
        "bob.manager@company.com",
        "sarah@company.com",
        """Hi Sarah,

Here are the notes from our sync. I've updated the Jira board with the new tasks using the standard workflow.

Please search for "Q1 Goals" in our internal Confluence (wiki.company.com) to see the full spec.

Thanks,
Bob
""",
    )

    # 3. Community Newsletter (External but safe, white-listed domain context)
    save_email(
        "legit_3_newsletter.eml",
        "Python Weekly - Issue #500",
        "newsletter@python.org",
        "dev@company.com",
        """Welcome to Python Weekly!

This week we explore the new features in Python 3.12.
Read more at: https://www.python.org/downloads/

Community Events:
- PyCon 2025: https://us.pycon.org/

Happy Coding!
""",
    )

    # --- SUSPICIOUS SAMPLES (Aim for High Scores / Critical) ---

    # 4. Urgent Password Reset (Classic Phishing)
    save_email(
        "sus_1_password.eml",
        "URGENT: Password Expiry Notification",
        "security-alert@micr0soft-support.tk",
        "victim@company.com",
        """Your Microsoft 365 password expires in 2 hours.
Retain access by validating your credentials immediately.

CLICK HERE TO VERIFY:
http://login-microsoft-secure-update.tk/auth/login.php

Failure to act will result in account suspension.
""",
    )

    # 5. CEO Wire Transfer (BEC - No links, pure social engineering)
    save_email(
        "sus_2_ceo_fraud.eml",
        "Urgent Wire Transfer Request",
        "ceo-private-email@gmail.com",
        "cfo@company.com",
        """Hi,

I am in a meeting and can't talk.
I need you to process an urgent wire transfer for a new vendor immediately.
The amount is $45,500.

Please reply with the confirmation once done so I can show the client.
Do not delay.

Sent from my iPhone
""",
    )

    # 6. Fake Invoice (Attachment + malicious context)
    # Using a dummy byte string for zip
    dummy_zip = b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x9a\x9b\x9c..."

    save_email(
        "sus_3_invoice.eml",
        "OVERDUE Invoice #9921",
        "accounting@billing-service-update.ga",
        "finance@company.com",
        """Please find attached the overdue invoice.
Remit payment immediately to avoid legal action.

See attached: Invoice_9921_Scan.zip.exe

Regards,
Collection Dept
""",
        attachments=[("Invoice_9921.zip.exe", dummy_zip)],
    )


if __name__ == "__main__":
    create_samples()
