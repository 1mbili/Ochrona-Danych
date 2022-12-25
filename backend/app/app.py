import bleach
import bcrypt
import time
import markdown
import secrets
from os import getenv
from flask import Flask, flash, request, redirect, make_response, url_for
from flask import render_template
from dotenv import load_dotenv
from utils import validate_token, create_username_jwt, validate_password, encrypt_password, encrypt_note, decrypt_note, create_restore_jwt
from datetime import datetime, timedelta
from emails import send_email, send_temp_code
from db_manager import DBManager
load_dotenv(verbose=True)

JWT_SECRET = getenv("JWT_SECRET")
SECRET_CREDENTIALS = getenv("FLASK_SECRET_KEY")
PEPPER = getenv("PEPPER")
app = Flask(__name__)
app.secret_key = SECRET_CREDENTIALS


DB = DBManager(password_file='/run/secrets/db-password')
DB.Create_Tables()


@app.route("/", methods=["GET"])
def index():
    jwt = request.cookies.get("jwt")
    if jwt_data := validate_token(jwt):
        remote_ip = request.environ['REMOTE_ADDR']
        username = jwt_data["username"]
        DB.cursor.execute("INSERT INTO Logins (username, time, remote_ip, result) VALUES (%s, %s, %s, %s)",
                          (username, time.strftime("%Y-%m-%d %H:%M:%S"), remote_ip, "1"))
        check_if_new_ip(username, remote_ip)
        return redirect(url_for('user', username=username), code=302)
    return redirect("/authenticate", code=302)


@app.route("/user/<username>", methods=["GET"])
def user(username):
    jwt = request.cookies.get("jwt")
    jwt_data = validate_token(jwt)
    if jwt_data and jwt_data["username"] == username:
        notes = get_notes(username)
        return render_template("homepage.html", username=username, notes=notes)
    return redirect("/authenticate", code=302)


@app.route("/user/addNote", methods=["POST"])
def add_note():
    jwt = request.cookies.get("jwt")
    if jwt_data := validate_token(jwt):
        title = bleach.clean(request.form.get("title", ""))
        markdown = bleach.clean(request.form.get("markdown", ""))
        encrypted = bleach.clean(request.form.get("encrypt", '0'))
        public = bleach.clean(request.form.get("public", '0'))
        if title == "" or markdown == "":
            return "Empty note", 204
        if encrypted == "on":
            title, markdown = encrypt_note(title, markdown)
            encrypted = '1'
        if public == "on":
            public = '1'
        DB.cursor.execute(
            "SELECT id FROM Users WHERE username = %s", (jwt_data["username"],))
        owner_id = DB.cursor.fetchone()[0]
        DB.cursor.execute("INSERT INTO Notes (owner_id, title, content, encrypted, public) VALUES (%s, %s, %s, %s, %s)",
                          (owner_id, title, markdown, encrypted, public))
        DB.connection.commit()
        return redirect(url_for('user', username=jwt_data["username"]), code=302)
    return "Unauthorized", 401


@app.route("/authenticate", methods=["GET"])
def get_authenticate():
    return render_template("login-form.html")


@app.route("/authenticate", methods=["POST"])
def authenticate():
    time.sleep(0.25)
    subpages = ["register", "restore_acces"]
    if "auth" not in request.form.keys():
        for subpage in subpages:
            if subpage in request.form.keys():
                return redirect("/" + subpage, code=302)
    username = bleach.clean(request.form.get("username", ""))
    password = bleach.clean(request.form.get("password", ""))
    if any([username == "", password == ""]):
        flash("Wypełnij wszystkie pola", 'error-msg')
        return redirect(request.url)
    if check_if_user_is_timeouted(username):
        flash("Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 3 minuty")
        return redirect("/authenticate", code=302)
    try:
        DB.cursor.execute(
            "SELECT password FROM Users WHERE username = %s", (username,))
        password_in_db = DB.cursor.fetchone()[0]
        condiction = bcrypt.checkpw(bytes(password+PEPPER, "utf-8"), password_in_db.encode("utf-8"))
        if condiction:
            print("123") 
            response = redirect(url_for('user', username=username), code=302)
            response.set_cookie("jwt", create_username_jwt(
                username, JWT_SECRET), secure=True, samesite="Strict")
            return response
        raise Exception()
    except:
        flash('Niepoprawna nazwa użytkownika lub hasło')
        remote_ip = request.environ['REMOTE_ADDR']
        try:
            DB.cursor.execute("INSERT INTO Logins (username, time, remote_ip, result) VALUES (%s, %s, %s, %s)",
                            (username, time.strftime("%Y-%m-%d %H:%M:%S"), remote_ip, "0"))
            DB.connection.commit()
            set_timeout_if_needed(username)
        finally:
            return redirect(request.url)


def set_timeout_if_needed(username: str):
    try:
        nth_last_login = get_nth_login(username, 5)
        time_now = datetime.now()
        dateTime_5mins_ago = time_now + timedelta(minutes=-5)
        if nth_last_login > dateTime_5mins_ago:
            DB.cursor.execute("INSERT INTO Timeouts (username, expire_time) VALUES (%s, %s)", (
                username, (time_now + timedelta(minutes=3)).strftime("%Y-%m-%d %H:%M:%S")))
            DB.connection.commit()
    except:
        return


def get_nth_login(username: str, nth_login: str):
    DB.cursor.execute(
        "SELECT time FROM Logins WHERE username = %s AND result = false ORDER BY time DESC LIMIT 1 OFFSET %s", (username, nth_login))
    try:
        return DB.cursor.fetchone()[0]
    except:
        raise Exception("Not enough logins")


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


@app.route("/register", methods=["GET"])
def get_register():
    return render_template("register-form.html")


@app.route("/register", methods=["POST"])
def register():
    username = bleach.clean(request.form.get("username", ""))
    password = bleach.clean(request.form.get("password", ""))
    email = bleach.clean(request.form.get("email", ""))
    if any([username == "", password == "", email == ""]):
        flash("Wypełnij wszystkie pola", 'error-msg')
        return redirect(request.url)
    msg, creds_check = validate_password(password)
    if creds_check is False:
        flash(msg, 'error-msg')
        return redirect(request.url)
    DB.cursor.execute(
        "SELECT username FROM Users WHERE username = %s", (username,))
    if DB.cursor.fetchone() is not None:
        flash("Użytkownik z taką nazwą już istnieje", 'error-msg')
        return redirect(request.url)
    password = encrypt_password(password)
    DB.cursor.execute(
        "INSERT INTO Users (username, password, email) VALUES (%s, %s, %s)", (username, password, email))
    DB.connection.commit()
    response = redirect("/authenticate", code=302)
    return response


@app.route("/notes", methods=["GET"])
def user_notes():
    jwt = request.cookies.get("jwt")
    if jwt_data := validate_token(jwt):
        DB.cursor.execute(
            "SELECT id FROM Users WHERE username = %s", (jwt_data["username"],))
        owner_id = DB.cursor.fetchone()[0]
        DB.cursor.execute(
            "SELECT id, title, content, encrypted, public FROM Notes WHERE owner_id = %s", (owner_id,))
        notes = DB.cursor.fetchall()
        notes_markdown = []
        for note in notes:
            notel = list(note)
            notel[2] = markdown.markdown(notel[2])
            notes_markdown.append(notel)
        return notes_markdown
    return "Unauthorized", 401


def get_notes(username: str):
    try:
        DB.cursor.execute(
            "SELECT id FROM Users WHERE username = %s", (username,))
        owner_id = DB.cursor.fetchone()[0]
        DB.cursor.execute(
            "SELECT id, title, content, encrypted, public FROM Notes WHERE owner_id = %s ORDER BY id ASC", (owner_id,))
        notes = DB.cursor.fetchall()
        notes_markdown = []
        for note in notes:
            notel = list(note)
            notel[2] = bleach.clean(markdown.markdown(notel[2]) )
            notes_markdown.append(notel)
        return notes_markdown
    except:
        return []


@app.route("/logout", methods=["GET"])
def logout():
    response = redirect("/", code=302)
    response.set_cookie("jwt", "", expires=0)
    return response


@app.route("/user/changeNotesSettings", methods=["POST"])
def change_notes_settings():
    jwt = request.cookies.get("jwt")
    if jwt_data := validate_token(jwt):
        client_data = request.json['value']
        DB.cursor.execute(
            "SELECT id FROM Users WHERE username = %s", (jwt_data["username"],))
        owner_id = DB.cursor.fetchone()[0]
        DB.cursor.execute(
            "SELECT id, title, content, encrypted, public FROM Notes WHERE owner_id = %s ORDER BY id ASC", (owner_id,))
        notes = DB.cursor.fetchall()
        if len(notes) != len(client_data):
            return "Błąd  ", 401
        for i, (note, user_val) in enumerate(zip(notes, client_data)):
            if user_val[0] == '1' and not note[3]:
                title_new, text_new = encrypt_note(note[1], note[2])
                DB.cursor.execute(
                    "UPDATE Notes SET title = %s, content = %s, encrypted = %s, public = %s WHERE id = %s", (title_new, text_new, user_val[0], user_val[1], i+1))
            elif user_val[0] == '0' and note[3] :
                title_new, text_new = decrypt_note(note[1], note[2])
                DB.cursor.execute(
                    "UPDATE Notes SET title = %s, content = %s, encrypted = %s, public = %s WHERE id = %s", (title_new, text_new, user_val[0], user_val[1], i+1))
            else:
                DB.cursor.execute(
                    "UPDATE Notes SET encrypted = %s, public = %s WHERE id = %s", (user_val[0], user_val[1], i+1))
            DB.connection.commit()
        return "OKi", 204
    return "Unauthorized", 401


@app.route("/restore_acces", methods=["GET", "POST"])
def restore_acces():
    if request.method == "GET":
        response = make_response(render_template("restore_acces.html"))
        response.set_cookie("email", "", expires=0)
        response.set_cookie("username", "", expires=0)
        return response
    try:
        username = bleach.clean(request.form.get("username", ""))
        DB.cursor.execute("SELECT email, id FROM Users WHERE username = %s;", (username,))
        email, id = DB.cursor.fetchone()
        auth_secret = secrets.token_urlsafe(12)
        expire_time = datetime.now() + timedelta(minutes=30)
        DB.cursor.execute("INSERT INTO TEMP_CODES (user_id, code, expire_time) VALUES (%s, %s, %s)", (id, auth_secret, expire_time))
        DB.connection.commit()
        print("AYAYA")
        mail_list = [email]
        send_temp_code(mail_list, auth_secret)
        response = redirect("/restore_acces/verify", code=302)
        response.set_cookie("restore_acces", create_restore_jwt(
                username, JWT_SECRET), httponly=True, samesite="Strict")
        return response
    except Exception as e:
        print(e)
        flash("Nie ma takiego użytkownika", 'error-msg')
        return redirect(request.url)


@app.route("/restore_acces/verify", methods=["GET", "POST"])
def set_new_password():
    """Update password for user"""
    if request.method == "GET":
        return render_template("verify.html")
    jwt = request.cookies.get("restore_acces")
    if jwt_restore_data := validate_token(jwt):
        token = bleach.clean(request.form.get("token", ""))
        new_password = bleach.clean(request.form.get("new_password", ""))
        new_password_conf = bleach.clean(request.form.get("new_password_conf", ""))
        if new_password != new_password_conf:
            flash("Hasła nie są takie same")
            return redirect(request.url)
        msg, creds_check = validate_password(new_password)
        if creds_check is False:
            flash(msg)
            return redirect(request.url)
        username = jwt_restore_data['username_restore']
        DB.cursor.execute(" \
        SELECT TEMP_CODES.code, TEMP_CODES.expire_time, TEMP_CODES.user_id \
        FROM TEMP_CODES  \
        INNER JOIN Users ON TEMP_CODES.user_id = Users.id  \
        WHERE Users.username = %s \
        ORDER By id_code DESC LIMIT 1 \
        ", (username,))
        code, expire_time, user_id = DB.cursor.fetchone()
        print(code, token)
        if code != token:
            flash("Błędny kod")
            return redirect(request.url)
        if expire_time < datetime.now():
            flash("Kod wygasł")
            return redirect(request.url)
        DB.cursor.execute("DELETE FROM TEMP_CODES WHERE user_id = %s", (user_id,))
        DB.connection.commit()
        DB.cursor.execute("UPDATE Users SET password = %s WHERE id = %s", (encrypt_password(new_password), user_id))
        DB.connection.commit()
        response = redirect("/", code=302)
        response.set_cookie("restore_acces", "", secure=True, expires=0)
        return response
    return redirect("/restore_acces")