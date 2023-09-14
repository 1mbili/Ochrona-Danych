"""
Module for handling encryptions
"""
import base64
import bcrypt
from os import getenv
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from azure_handler import AzureHandler
load_dotenv(verbose=True)

az_handler = AzureHandler()
PEPPER = az_handler.get_secret("PEPPER")
AES_KEY = az_handler.get_secret("AES-KEY").encode()


def encrypt_password(password: str) -> bytes:
    """Encrypt password with bcrypt"""
    return bcrypt.hashpw(bytes(password+PEPPER, "utf-8"), bcrypt.gensalt())


def check_password(password: str, hashed_password: bytes) -> bool:
    """Check if password is correct"""
    
    return bcrypt.checkpw(bytes(password+PEPPER, "utf-8"), hashed_password)


def encrypt_note(markdown: str) -> tuple:
    """Encrypt note"""
    markdown = aes_encrypt(markdown)
    return markdown


def decrypt_note(markdown: str) -> tuple:
    """Decrypt note"""
    markdown = aes_decrypt(markdown).decode("utf-8")
    return markdown


def aes_encrypt(text: str) -> str:
    """Encrypt text with key"""
    iv = get_random_bytes(16)
    aes = AES.new(AES_KEY, AES.MODE_CBC, iv)
    encrypted_data = aes.encrypt(pad(text.encode(), 16))
    return base64.b64encode(iv+encrypted_data)


def aes_decrypt(text: str) -> str:
    """Decrypt text with key"""
    text = base64.b64decode(text)
    iv, msg = text[:16], text[16:]
    aes = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(aes.decrypt(msg), 16)
    return decrypted_data
