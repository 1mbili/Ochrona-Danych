import mysql.connector
from utils import encrypt_password


class DBManager:
    def __init__(self, database='Notatnix', host="mysql", user="root", password_file=None):
        pf = open(password_file, 'r', encoding='utf-8')
        self.connection = mysql.connector.connect(
            user=user,
            password=pf.read(),
            host=host,  # name of the mysql service as set in the docker compose file
            database=database
        )
        pf.close()
        self.cursor = self.connection.cursor(buffered=True)

    def Create_Tables(self):
        password = encrypt_password("admin")
        self.cursor.execute("DROP TABLE IF EXISTS TEMP_CODES")
        self.cursor.execute("DROP TABLE IF EXISTS Notes")
        self.cursor.execute("DROP TABLE IF EXISTS Timeouts")
        self.cursor.execute("DROP TABLE IF EXISTS Logins")
        self.cursor.execute("DROP TABLE IF EXISTS Users")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL)")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Notes (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255) NOT NULL, content MEDIUMTEXT NOT NULL, encrypted BOOLEAN, public BOOLEAN, owner_id INT, FOREIGN KEY (owner_id) REFERENCES Users(id))")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Logins (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, time DATETIME NOT NULL, remote_ip VARCHAR(255) NOT NULL, result BOOLEAN)")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Timeouts (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, expire_time DATETIME NOT NULL)")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TEMP_CODES (id_code INT AUTO_INCREMENT PRIMARY KEY, user_id INT, FOREIGN KEY (user_id) REFERENCES Users(id), code VARCHAR(255), expire_time DATETIME )")
        self.cursor.execute(
            "INSERT INTO Users (username, password, email) VALUES ('admin', %s, 'mailgrupowy755@gmail.com')", (password, ))
        self.connection.commit()
