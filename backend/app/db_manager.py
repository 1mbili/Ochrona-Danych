import mysql.connector
from encryption_utils import encrypt_password

TEXT = """
# Herboso iaculum quando

## Ter onus coniunx passi iuvenalis parte

Lorem markdownum vulgus, nomine pudore! Coma ora tenet, animo deficeret
conveniunt tale verberis: hoc!

> Heros cereris, exit verba Neptunus movet eripuit fallebat inplet certae [sua
> opposuitque](http://conantur-proximus.com/rebellescaput). Solidumque
> recentibus damnarat beatam contigit dixit hominemque Enipeu. Orio mecum *modus
> parum*, pereat relicta cantusque. Movebo iste Belides hic sint vulnera viaque,
> [en viscere flexere](http://haec-tamen.org/opus-nostras.php) fraudare. Herbis
> verba illa submovet antiquum passu; forsitan maduisse faciem meritum haeret
> secum pertimuitque pasci illo, seu.

## Amor campi in unum Iovis est erit

Iuncta blanditias barbariam luctus defuit. Et sumus suam precari flagrantemque
Cauno.

> Nostris modo dies Paridis timori: qua Iris rictus dux ipsaque vestram enim
> unda *antiquarum*, somnia remisit. Membra Antimachumque mulcere paulatimque
> contingere spectat adclivis candida regis. Occiduae sed; ubi plangitur non
> nutantem fuerunt Sirenum paventque rerumque nomina *nec*, vel visa deos sit
> sonum. Caelebs retia, Lycaoniae et quod fulmineos, quo natus, suis atque
> partem, nec nocti audacem nota.

Mea sibi tulit specie et cuius petitur Interea habitare ostendit **Troiana**;
nova perhorruit mundi, et est conduntur resurgere. Fulvis undis altoque Alcyone.

## Socialis differt tu credis tamen saepe quota

Parens moenia. Sed mandata; flavum Persea grates excepit similis: lascivaque.
Est vaccae, humi rupe tamen mea fuerat animum mortale aversa, et credere, qui
licet sorbent **male** fatalis. Nomen dea Graias tuae patula aera deque illa
Macareu carmine, equorum Phoebe: singula! Fata notissima plura scitaris doles
rore turpius qui Mavortis **huic multum** tegmina.

    if (4 != sprite_terabyte_optical + parameter_internet - of * unc) {
        pointTrackback = kofficeBlog;
    }
    beta += editor;
    if (srgb <= 5 - propertyIphoneApple) {
        systrayRdfFormat(virusOpticalDvd, playDesktop(application,
                desktop_dashboard));
        clock_tablet -= 3 + 5;
    } else {
        diskSoftware = 2;
        cifs.heap_url = 63 + ramD * affiliate;
    }
    optical_raster = open_card_network;
    switch_unc_apache += richPopCamera(upnp, server, leafCaps(driveMenuPaste,
            system + pushDma, contextualEmulationFi));

Tanti tamen stantibus cruribus obstaret inane, tellus, tellus ducem, curvique
dolentem. In mora, suo Theseus succincta huic, ver deum fores in Dicta crura
nescit Si.



"""


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

    def debug_propagate_db(self):
        # DEBUG ONLY
        password = encrypt_password("admin")
        password_Jarek = encrypt_password("bob")
        self.cursor.execute(
            "INSERT INTO Users (username, password, email) VALUES ('admin', %s, 'mailgrupowy755@gmail.com')", (password, ))
        self.cursor.execute(
            "INSERT INTO Notes (title, content, encrypted, public, owner_id) VALUES ('Test', 'Test', 0, 1, 1)")
        self.cursor.execute(
            "INSERT INTO Users (username, password, email) VALUES ('Jarek', %s, 'mailgrupowy755@gmail.com')", (password_Jarek, ))
        self.cursor.execute(
            "INSERT INTO Notes (title, content, encrypted, public, owner_id) VALUES ('Lorem ipsum', %s, 0, 1, 2)", (TEXT, ))
        self.connection.commit()

    def Create_Tables(self):
        self.cursor.execute("DROP TABLE IF EXISTS TEMP_CODES")
        self.cursor.execute("DROP TABLE IF EXISTS Notes")
        self.cursor.execute("DROP TABLE IF EXISTS Timeouts")
        self.cursor.execute("DROP TABLE IF EXISTS Logins")
        self.cursor.execute("DROP TABLE IF EXISTS Users")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, password VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL,  UNIQUE (username))")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Notes (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255) NOT NULL, content MEDIUMTEXT NOT NULL, encrypted BOOLEAN, public BOOLEAN, owner_id INT, FOREIGN KEY (owner_id) REFERENCES Users(id))")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Logins (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, time DATETIME NOT NULL, remote_ip VARCHAR(255) NOT NULL, result BOOLEAN)")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS Timeouts (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(255) NOT NULL, expire_time DATETIME NOT NULL)")
        self.cursor.execute(
            "CREATE TABLE IF NOT EXISTS TEMP_CODES (id_code INT AUTO_INCREMENT PRIMARY KEY, user_id INT, FOREIGN KEY (user_id) REFERENCES Users(id), code VARCHAR(255), expire_time DATETIME )")
        self.connection.commit()
