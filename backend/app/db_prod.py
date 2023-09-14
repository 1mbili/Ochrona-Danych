from db_manager import DBManager
from azure_handler import AzureHandler

az_handler = AzureHandler()
db_pass = az_handler.get_secret("mysql-password")
az_user = az_handler.get_secret("mysql-user")
az_hostname = az_handler.get_secret("mysql-host")
db = DBManager(db_pass, az_hostname, az_user)


db.Create_Tables()


