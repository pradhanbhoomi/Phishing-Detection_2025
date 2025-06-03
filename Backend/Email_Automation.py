import smtplib
from email.message import EmailMessage

# Get user input
sender_email = input("Enter your Gmail address: ")
app_password = input("Enter your Gmail app password: ")
receiver_email = input("Enter recipient's email address: ")
subject = input("Enter subject: ")
body = input("Enter the message body:\n")

# Create the email
msg = EmailMessage()
msg["From"] = sender_email
msg["To"] = receiver_email
msg["Subject"] = subject
msg.set_content(body)

# Send the email
try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)
    print(f"\n✅ Email sent successfully to {receiver_email}")
except Exception as e:
    print(f"\n❌ Failed to send email: {e}")
