from db_manager import DBManager

db = DBManager(password_file='/run/secrets/db-password')
db.Create_Tables()


