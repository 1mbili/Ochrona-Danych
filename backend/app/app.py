from encryption_utils import encrypt_password, encrypt_note, decrypt_note, check_password
from azure_handler import AzureHandler
from db_manager import DBManager
from emails import send_temp_code
from jwt_utils import create_username_jwt, create_restore_jwt, validate_token
from utils import validate_password, login_required, set_timeout_if_needed, \
    check_if_new_ip, check_if_user_is_timeouted, check_honeypot
import bleach
import time
import markdown
import secrets
from os import getenv
from flask import Flask, flash, request, redirect, make_response, Blueprint
from flask import render_template
from datetime import datetime, timedelta
from dotenv import load_dotenv
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv(verbose=True)
if getenv("FLASK_ENV") == "k8s":
    db_pass = getenv("mysql-password")
    az_user = getenv("mysql-user")
    az_hostname = getenv("mysql-host")
    az_port = getenv("mysql-port")
    flask_key = getenv('FLASK-SECRET-KEY')
else:
    az_handler = AzureHandler()
    db_pass = az_handler.get_secret("mysql-password")
    az_user = az_handler.get_secret("mysql-user")
    az_hostname = az_handler.get_secret("mysql-host")
    az_port = az_handler.get_secret("mysql-port")
    flask_key = az_handler.get_secret("FLASK-SECRET-KEY")
default = Blueprint("default", __name__, url_prefix="")


def create_app():
    app = Flask(__name__)
    app.secret_key = flask_key
    app.register_blueprint(default)
    app = ProxyFix(app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    return app

DB = DBManager(db_pass, az_hostname, az_user, az_port, "defaultdb")


@default.route("/", methods=["GET"])
def index():
    jwt = request.cookies.get("jwt")
    if jwt_data := validate_token(jwt):
        remote_ip = request.environ['REMOTE_ADDR']
        username = jwt_data["username"]
        DB.cursor.execute("INSERT INTO Logins (username, time, remote_ip, result) VALUES (%s, %s, %s, %s)",
                          (username, time.strftime("%Y-%m-%d %H:%M:%S"), remote_ip, "1"))
        check_if_new_ip(username, remote_ip)
        return redirect(f"/user/{username}", code=302)
    return redirect("/authenticate", code=302)


@login_required
@default.route("/user/<username>", methods=["GET"])
def user(username):
    jwt = validate_token(request.cookies.get("jwt"))
    if jwt and username == jwt["username"]:
        return render_template("homepage.html", username=username)
    return "Unauthorized", 401


@login_required
@default.route("/user/addNote", methods=["POST"])
def add_note():
    jwt_data = validate_token(request.cookies.get("jwt"))
    title = bleach.clean(request.form.get("title", ""))
    markdown_note = bleach.clean(request.form.get("markdown", ""))
    encrypted = bleach.clean(request.form.get("encrypt", ''))
    public = bleach.clean(request.form.get("public", '0'))
    password = None
    if title == "" or markdown_note == "":
        return "Empty note", 204
    if encrypted != "":
        markdown_note = encrypt_note(markdown_note)
        password = encrypt_password(encrypted)
    if public == "on":
        public = '1'
    DB.cursor.execute(
        "SELECT id FROM Users WHERE username = %s", (jwt_data["username"],))
    owner_id = DB.cursor.fetchone()[0]
    DB.cursor.execute("INSERT INTO Notes (owner_id, title, content, encrypted, public) VALUES (%s, %s, %s, %s, %s)",
                      (owner_id, title, markdown_note, password, public))
    DB.connection.commit()
    return redirect(f"/user/{jwt_data['username']}", code=302)


@default.route("/authenticate", methods=["GET"])
def get_authenticate():
    return render_template("login-form.html")


@default.route("/authenticate", methods=["POST"])
def authenticate():
    time.sleep(0.25)
    subpages = ["register", "restore_acces", "anonymous_view"]
    if "auth" not in request.form.keys():
        for subpage in subpages:
            if subpage in request.form.keys():
                return redirect("/" + subpage, code=302)
    username = bleach.clean(request.form.get("username", ""))
    password = bleach.clean(request.form.get("password", ""))
    if uri := check_honeypot(username):
        return render_template(f"{uri}.html")
    if any([username == "", password == ""]):
        flash("Wypełnij wszystkie pola", 'error-msg')
        return redirect("/authenticate", code=302)
    if check_if_user_is_timeouted(username):
        flash("Zbyt wiele nieudanych prób logowania. Spróbuj ponownie za 3 minuty")
        return redirect("/authenticate", code=302)
    try:
        DB.cursor.execute(
            "SELECT password FROM Users WHERE username = %s", (username,))
        password_in_db = DB.cursor.fetchone()[0]
        condiction = check_password(password, password_in_db.encode("utf-8"))
        if condiction:
            response = redirect(f"/", code=302)
            response.set_cookie("jwt", create_username_jwt(
                username), httponly=True)
            return response
    except:
        flash('Niepoprawna nazwa użytkownika lub hasło')
        remote_ip = request.environ['REMOTE_ADDR']
        try:
            DB.cursor.execute("INSERT INTO Logins (username, time, remote_ip, result) VALUES (%s, %s, %s, %s)",
                              (username, time.strftime("%Y-%m-%d %H:%M:%S"), remote_ip, "0"))
            DB.connection.commit()
            set_timeout_if_needed(username)
        except Exception as e:
            print(e)
    return redirect("/authenticate", code=302)


@default.route("/register", methods=["GET"])
def get_register():
    return render_template("register-form.html")


@default.route("/register", methods=["POST"])
def register():
    username = bleach.clean(request.form.get("username", ""))
    password = bleach.clean(request.form.get("password", ""))
    email = bleach.clean(request.form.get("email", ""))
    if any([username == "", password == "", email == ""]):
        flash("Wypełnij wszystkie pola", 'error-msg')
        return redirect("/authenticate")
    msg, creds_check = validate_password(password)
    if creds_check is False:
        flash(msg, 'error-msg')
        return redirect("/register")
    if "admin" in username:
        flash("Nie wolno tworzyć kont z nazwą admin", 'error-msg')
        return redirect("/register")
    DB.cursor.execute(
        "SELECT username FROM Users WHERE username = %s", (username,))
    if DB.cursor.fetchone() is not None:
        flash("Użytkownik z taką nazwą już istnieje", 'error-msg')
        return redirect("/register")
    password = encrypt_password(password)
    DB.cursor.execute(
        "INSERT INTO Users (username, password, email) VALUES (%s, %s, %s)", (username, password, email))
    DB.connection.commit()
    response = redirect("/authenticate", code=302)
    return response


@login_required
@default.route("/notes", methods=["GET"])
def user_notes():
    jwt_data = validate_token(request.cookies.get("jwt"))
    DB.cursor.execute(
        "SELECT id FROM Users WHERE username = %s", (jwt_data["username"],))
    owner_id = DB.cursor.fetchone()[0]
    DB.cursor.execute(
        "SELECT id, title, content, public FROM Notes WHERE owner_id = %s", (owner_id,))
    notes = DB.cursor.fetchall()
    notes_markdown = []
    for note in notes:
        notel = list(note)
        notel[2] = markdown.markdown(notel[2])
        notes_markdown.append(notel)
    return notes_markdown


@default.route("/logout", methods=["GET"])
def logout():
    response = redirect("/", code=302)
    response.set_cookie("jwt", b"", expires=0)
    return response


@login_required
@default.route("/user/changeNotesSettings", methods=["POST"])
def change_notes_settings():
    jwt_data = validate_token(request.cookies.get("jwt"))
    client_data = request.json['value']
    print(client_data)
    DB.cursor.execute(
        "SELECT id FROM Users WHERE username = %s", (jwt_data["username"],))
    owner_id = DB.cursor.fetchone()[0]
    DB.cursor.execute(
        "SELECT id, title, content, encrypted, public FROM Notes WHERE owner_id = %s ORDER BY id ASC", (owner_id,))
    notes = DB.cursor.fetchall()
    if len(notes) != len(client_data):
        return "Błąd", 401
    for note, user_val in zip(notes, client_data):
        note_id = int(user_val[0])
        encrypted_password = bleach.clean(user_val[1])
        is_public = int(user_val[2])
        if encrypted_password != "" and not note[3]:
            text_new = encrypt_note(note[2])
            password = encrypt_password(encrypted_password)
            DB.cursor.execute(
                "UPDATE Notes SET content = %s, encrypted = %s, public = %s WHERE id = %s", (text_new, password, is_public, note_id))
        elif note[3] and check_password(encrypted_password, note[3].encode("utf-8")):
            text_new = decrypt_note(note[2])
            DB.cursor.execute(
                "UPDATE Notes SET content = %s, encrypted = %s, public = %s WHERE id = %s", (text_new, None, is_public, note_id))
        else:
            DB.cursor.execute(
                "UPDATE Notes SET public = %s WHERE id = %s", (is_public, note_id))
        DB.connection.commit()
    return "OK", 204


@default.route("/restore_acces", methods=["GET", "POST"])
def restore_acces():
    if request.method == "GET":
        return make_response(render_template("restore_acces.html"))
    try:
        username = bleach.clean(request.form.get("username", ""))
        DB.cursor.execute(
            "SELECT email, id FROM Users WHERE username = %s;", (username,))
        email, id = DB.cursor.fetchone()
        auth_secret = secrets.token_urlsafe(12)
        expire_time = datetime.now() + timedelta(minutes=30)
        DB.cursor.execute(
            "INSERT INTO TEMP_CODES (user_id, code, expire_time) VALUES (%s, %s, %s)", (id, auth_secret, expire_time))
        DB.connection.commit()
        mail_list = [email]
        send_temp_code(mail_list, auth_secret)
        response = redirect("/restore_acces/verify", code=302)
        response.set_cookie("restore_acces", create_restore_jwt(
            username), secure=True, httponly=True, samesite="Strict")
        return response
    except Exception as e:
        print(e)
        flash("Nie ma takiego użytkownika", 'error-msg')
        return redirect("/authenticate")


@default.route("/restore_acces/verify", methods=["GET", "POST"])
def set_new_password():
    """Update password for user"""
    if request.method == "GET":
        return render_template("verify.html")
    jwt = request.cookies.get("restore_acces")
    if jwt_restore_data := validate_token(jwt):
        token = bleach.clean(request.form.get("token", ""))
        new_password = bleach.clean(request.form.get("new_password", ""))
        new_password_2 = bleach.clean(
            request.form.get("new_password_conf", ""))
        print(new_password, new_password_2)
        if new_password != new_password_2:
            flash("Hasła nie są takie same")
            return redirect("/restore_acces/verify")
        msg, creds_check = validate_password(new_password)
        if creds_check is False:
            flash(msg)
            return redirect("/restore_acces/verify")
        username = jwt_restore_data['username_restore']
        DB.cursor.execute(" \
        SELECT TEMP_CODES.code, TEMP_CODES.expire_time, TEMP_CODES.user_id \
        FROM TEMP_CODES  \
        INNER JOIN Users ON TEMP_CODES.user_id = Users.id  \
        WHERE Users.username = %s \
        ORDER By id_code DESC LIMIT 1 \
        ", (username,))
        code, expire_time, user_id = DB.cursor.fetchone()
        if code != token:
            flash("Błędny kod")
            return redirect("/restore_acces/verify")
        if expire_time < datetime.now():
            flash("Kod wygasł")
            return redirect("/restore_acces/verify")
        DB.cursor.execute(
            "DELETE FROM TEMP_CODES WHERE user_id = %s", (user_id,))
        DB.connection.commit()
        DB.cursor.execute("UPDATE Users SET password = %s WHERE id = %s",
                          (encrypt_password(new_password), user_id))
        DB.connection.commit()
        response = redirect("/", code=302)
        response.set_cookie("restore_acces", "", secure=True,
                            httponly=True, expires=0)
        return response
    return redirect("/restore_acces")


@default.route("/anonymous_view", methods=["GET"])
def anonymous_view():
    return render_template("public_notes.html")


@default.route("/public_notes", methods=["GET"])
def public_notes():
    try:
        DB.cursor.execute(
            "SELECT u.id, u.username, n.title, n.content FROM Notes n INNER JOIN Users u ON n.owner_id = u.id WHERE public = 1 AND encrypted is NULL ORDER BY id ASC")
        notes = DB.cursor.fetchall()
        notes_markdown = []
        for note in notes:
            notel = list(note)
            notel[3] = markdown.markdown(notel[3])
            notes_markdown.append(notel)
        return notes_markdown
    except:
        return "Błąd", 500
