#!/bin/bash
#run docker image with environment variables
docker run --rm -it -p 8080:8080 -e KEY_VAULT_NAME=${KEY_VAULT_NAME} -e AZURE_TENANT_ID=${ARM_TENANT_ID} -e AZURE_CLIENT_ID=${ARM_CLIENT_ID} -e AZURE_CLIENT_SECRET=${ARM_CLIENT_SECRET} -e AZURE_SUBSCRIPTION_ID=${ARM_SUBSCRIPTION_ID} app:base

