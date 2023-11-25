from db_manager import DBManager
from azure_handler import AzureHandler

az_handler = AzureHandler()
db_pass = az_handler.get_secret("mysql-password")
az_user = az_handler.get_secret("mysql-user")
az_hostname = az_handler.get_secret("mysql-host")
az_port = az_handler.get_secret("mysql-port")
db = DBManager(db_pass, az_hostname, az_user, az_port)
db.create_database()
db.Create_Tables()
db.debug_propagate_db()


