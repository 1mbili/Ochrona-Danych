from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from os import getenv


class AzureHandler:
    def __init__(self) -> None:
        self.keyVaultName = getenv("KEY_VAULT_NAME")
        self.KVUri = f"https://{self.keyVaultName}.vault.azure.net"
        self.credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=self.KVUri, credential=self.credential)

    def get_secret(self, secret_name: str) -> str:
        return self.client.get_secret(secret_name).value