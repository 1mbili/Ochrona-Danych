import os
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
credential = DefaultAzureCredential()
keyVaultName = 'vault0a'
KVUri = f"https://{keyVaultName}.vault.azure.net"
client = SecretClient(vault_url=KVUri, credential=credential)
secretName = "mysql-host"
retrieved_secret = client.get_secret(secretName)

print(f"Your secret is '{retrieved_secret.value}'.")
