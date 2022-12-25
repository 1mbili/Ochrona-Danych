"""
Utils functions for flask app
"""
import base64
import secrets
import bcrypt
import string
import jwt
import math
from datetime import datetime, timedelta
from os import getenv
from dotenv import load_dotenv
from jwt import decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
load_dotenv(verbose=True)

PEPPER = getenv("PEPPER")
JWT_SECRET = getenv("JWT_SECRET")
AES_KEY = getenv("AES_KEY").encode()


def validate_password(password: str) -> bool:
    """Check if user password is valid"""
    if len(password) < 8:
        return "Zbyt krótkie hasło", False
    if not any(char.isdigit() for char in password):
        return "Hasło musi zawierać cyfrę", False
    print(calculate_entropy(password))
    if calculate_entropy(password) < 2.5:
        return "Hasło jest zbyt proste", False
    return "", True


def encrypt_password(password: str) -> bytes:
    """Encrypt password with bcrypt"""
    return bcrypt.hashpw(bytes(password+PEPPER, "utf-8"), bcrypt.gensalt())


def generate_state(length=30) -> str:
    """Generate random state"""
    return "".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(length))


def validate_token(token: str) -> bool:
    if token == "":
        return False
    try:
        decoded = decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except Exception as err:
        print(err)
        return False


def create_username_jwt(username: str, secret: str) -> str:
    dt = datetime.now() + timedelta(minutes=30)
    dane = {"username": username, "exp": dt}
    zeton = jwt.encode(dane, secret, "HS256")
    return zeton


def create_restore_jwt(username: str, secret: str) -> str:
    dt = datetime.now() + timedelta(minutes=30)
    dane = {"username_restore": username, "exp": dt}
    zeton = jwt.encode(dane, secret, "HS256")
    return zeton


def calculate_entropy(text: str) -> float:
    """Calculate entropy of text"""
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x)))/len(text)
        if p_x > 0:
            entropy += - p_x*math.log2(p_x)
    return entropy


def encrypt_note(title: str, markdown: str) -> tuple:
    """Encrypt note"""
    title = aes_encrypt(title)
    markdown = aes_encrypt(markdown)
    return title, markdown


def decrypt_note(title: str, markdown: str) -> tuple:
    """Decrypt note"""
    title = aes_decrypt(title).decode("utf-8")
    markdown = aes_decrypt(markdown).decode("utf-8")
    print("marrl", title, markdown)
    return title, markdown


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
