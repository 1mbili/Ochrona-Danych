#!/bin/bash

python3 /var/www/app/db_create.py
python3 -m gunicorn --bind 0.0.0.0:8080 manage:app
