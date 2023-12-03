from db_manager import DBManager
from azure_handler import AzureHandler

from os import getenv
if getenv("FLASK_ENV") == "k8s":
    db_pass = getenv("mysql-password")
    az_user = getenv("mysql-user")
    az_hostname = getenv("mysql-host")
    az_port = getenv("mysql-port")
else:
    az_handler = AzureHandler()
    db_pass = az_handler.get_secret("mysql-password")
    az_user = az_handler.get_secret("mysql-user")
    az_hostname = az_handler.get_secret("mysql-host")
    az_port = az_handler.get_secret("mysql-port")
db = DBManager(db_pass, az_hostname, az_user, az_port, "defaultdb")


db.Create_Tables()


