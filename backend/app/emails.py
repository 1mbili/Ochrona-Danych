"""
Module for sending emails
"""
import smtplib
import ssl
from email.message import EmailMessage
from os import getenv
from dotenv import load_dotenv
load_dotenv(verbose=True)


def send_email(recivers: list, message: str, title: str):
    sender = getenv("GMAIL_USER")
    password = getenv("GMAIL_PASS")
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
