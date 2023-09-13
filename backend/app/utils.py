"""
Utils functions for flask app
"""
from jwt_utils import validate_token
from emails import send_email
from db_manager import DBManager
import secrets
import string
import math
from functools import wraps
from dotenv import load_dotenv
from flask import request, redirect, url_for
from datetime import datetime, timedelta
load_dotenv(verbose=True)


ENTROPY_TRESHOLD = 3.25
DB = DBManager()


def validate_password(password: str) -> bool:
    """Check if user password is valid"""
    if len(password) < 8:
        return "Zbyt krótkie hasło", False
    if not any(char.isdigit() for char in password):
        return "Hasło musi zawierać cyfrę", False
    print(calculate_entropy(password))
    if calculate_entropy(password) < ENTROPY_TRESHOLD:
        return "Hasło jest zbyt proste", False
    return "", True


def generate_state(length=30) -> str:
    """Generate random state"""
    return "".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(length))


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

def login_required(f):
    """Veryfies if user has valid jwt token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not validate_token(request.cookies.get("jwt")):
            return redirect(url_for("authenticate"))
        return f(*args, **kwargs)
    return decorated_function


def set_timeout_if_needed(username: str):
    try:
        nth_last_login = get_nth_login(username, 5)
        time_now = datetime.now()
        dateTime_5mins_ago = time_now + timedelta(minutes=-5)
        print(nth_last_login, dateTime_5mins_ago)
        if nth_last_login > dateTime_5mins_ago:
            DB.cursor.execute("INSERT INTO Timeouts (username, expire_time) VALUES (%s, %s)", (
                username, (time_now + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")))
            DB.connection.commit()
    except Exception as e:
        print(e)


def get_nth_login(username: str, nth_login: str):
    DB.cursor.execute(
        "SELECT time FROM Logins WHERE username = %s AND result = false ORDER BY time DESC LIMIT 1 OFFSET %s", (username, nth_login))
    try:
        return DB.cursor.fetchone()[0]
    except:
        raise Exception("Za mało loginów")


def check_if_user_is_timeouted(username: str):
    DB.cursor.execute(
        "SELECT expire_time FROM Timeouts WHERE username = %s", (username,))
    try:
        expire_time = DB.cursor.fetchone()[0]
        time_now = datetime.now()
        if expire_time > time_now:
            return True
    except:
        return False


def check_if_new_ip(username: str, remote_ip: str):
    DB.cursor.execute(
        "SELECT remote_ip FROM Logins WHERE username = %s and remote_ip = %s", (username, remote_ip))
    if DB.cursor.fetchone() is None:
        msg = f"""
        Witaj {username}!
        Wykryto nowe połączenie z adresu IP: {remote_ip}.
        Pozdrawiamy,
        Zespół Notatnix
        """
        send_email(username, msg, "Zalogowano na nowym urządzeniu")


def check_honeypot(username: str) -> str:
    """Checks for honeypot based on username"""
    if username == "admin123":
        return "/honeypot1"
    if username == "admin ' or '1'='1":
        return "/honeypot2"
    return False