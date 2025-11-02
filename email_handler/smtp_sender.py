# email_handler/smtp_sender.py
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config

def format_encrypted_body(encrypted_parts):
    """Formats the encrypted data into a structured text block."""
    body = "---BEGIN ENCRYPTED MESSAGE---\n"
    body += json.dumps(encrypted_parts, indent=2)
    body += "\n---END ENCRYPTED MESSAGE---"
    return body

def send_email(recipient_email, subject, encrypted_body):
    """Sends an email via SMTP."""
    msg = MIMEMultipart()
    msg['From'] = Config.SMTP_USER
    msg['To'] = recipient_email
    msg['Subject'] = f"[ENCRYPTED] {subject}"

    msg.attach(MIMEText(encrypted_body, 'plain'))

    try:
        server = smtplib.SMTP(Config.SMTP_SERVER, Config.SMTP_PORT)
        server.starttls()
        server.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
        text = msg.as_string()
        server.sendmail(Config.SMTP_USER, recipient_email, text)
        server.quit()
        return True, "Email sent successfully!"
    except Exception as e:
        return False, f"Failed to send email: {e}"