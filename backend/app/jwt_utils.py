"""
Module for handling JWT tokens
"""
from datetime import datetime, timedelta
from jwt import decode, encode
from azure_handler import AzureHandler
from os import getenv
if getenv("FLASK_ENV") == "k8s":
    JWT_SECRET = getenv("JWT-SECRET")
else:
    az_handler = AzureHandler()
    JWT_SECRET = az_handler.get_secret("JWT-SECRET")


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
