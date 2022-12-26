"""
Module for handling JWT tokens
"""
from datetime import datetime, timedelta
from jwt import decode, encode
from os import getenv
from dotenv import load_dotenv
load_dotenv(verbose=True)

JWT_SECRET = getenv("JWT_SECRET")


def validate_token(token: str) -> bool:
    """Validate JWT token"""
    if token == "":
        return False
    try:
        decoded = decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except Exception as err:
        print(err)
        return False


def create_username_jwt(username: str) -> str:
    dt = datetime.now() + timedelta(minutes=30)
    dane = {"username": username, "exp": dt}
    zeton = encode(dane, JWT_SECRET, "HS256")
    return zeton


def create_restore_jwt(username: str) -> str:
    dt = datetime.now() + timedelta(minutes=30)
    dane = {"username_restore": username, "exp": dt}
    zeton = encode(dane, JWT_SECRET, "HS256")
    return zeton
