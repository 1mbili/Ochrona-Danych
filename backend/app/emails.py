"""
Module for sending emails
"""
import smtplib
import ssl
from email.message import EmailMessage
from os import getenv
from azure_handler import AzureHandler

if getenv("FLASK_ENV") == "k8s":
    sender = getenv("GMAIL-USER")
    password = getenv("GMAIL-PASS")
else:
    az_handler = AzureHandler()
    sender = az_handler.get_secret("GMAIL-USER")
    password = az_handler.get_secret("GMAIL-PASS")


def send_email(recivers: list, message: str, title: str):
    email_msg = EmailMessage()
    email_msg["From"] = sender
    email_msg["To"] = recivers
    email_msg["Subject"] = title
    email_msg.set_content(message)
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender, password)
            server.send_message(email_msg)
    except Exception as err:
        print(err)


def send_temp_code(recivers: list, code: str):
    """Function for sending emails"""
    message = f"""
    Witaj,
    Poniżej przesyłam kod do zmiany hasła:
    {code}
    Pozdrawiamy!
    """
    send_email(recivers, message, "Link do zmiany hasła")
